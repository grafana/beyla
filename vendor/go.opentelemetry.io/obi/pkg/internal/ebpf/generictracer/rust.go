// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	lru "github.com/hashicorp/golang-lru/v2"

	"go.opentelemetry.io/obi/internal/rustexec"
	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/uprobe"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

type rustTarget struct {
	lifecycle *exec.FileInfo
	links     []io.Closer
}

type rustController struct {
	tracer      *Tracer
	mu          sync.Mutex
	targets     map[app.PID]*rustTarget
	closed      bool
	attaching   sync.WaitGroup
	executables *lru.Cache[rustExecutableKey, *rustExecutable]
}

// rustAttachment is prepared without the controller lock. Only the PID's current
// target may publish it, because the BPF maps it writes are keyed by PID alone.
type rustAttachment struct {
	links             []io.Closer
	capabilities      BpfRustCapabilitiesT
	expectedStartTime uint64
}

func newRustController(tracer *Tracer) *rustController {
	return &rustController{
		tracer:      tracer,
		targets:     map[app.PID]*rustTarget{},
		executables: newRustExecutableCache(),
	}
}

func (c *rustController) allow(pid app.PID, fi *exec.FileInfo) {
	if fi == nil || fi.SDKLanguage() != svc.InstrumentableRust || fi.StartTime() == 0 {
		return
	}

	target := c.register(pid, fi)
	if target == nil {
		return
	}
	defer c.attaching.Done()

	// Reading the executable and attaching uprobes is slow: other PIDs must not wait on it.
	attachment, err := c.attach(pid, fi)
	c.commit(pid, target, attachment, err)
}

// register claims the PID for a new lifecycle, or returns nil when there is nothing to attach.
func (c *rustController) register(pid app.PID, fi *exec.FileInfo) *rustTarget {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed || c.tracer.bpfObjects.RustCapabilities == nil {
		return nil
	}

	if target := c.targets[pid]; target != nil {
		if target.lifecycle == fi {
			return nil
		}
		c.remove(pid)
	}

	// Remember unsupported binaries too, so discovery does not rescan them.
	target := &rustTarget{lifecycle: fi}
	c.targets[pid] = target
	c.attaching.Add(1)

	return target
}

// commit publishes an attachment only while its target still owns the PID. A PID
// blocked, replaced or closed during attachment only gets its new probes closed.
func (c *rustController) commit(pid app.PID, target *rustTarget, attachment rustAttachment, cause error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed || c.targets[pid] != target {
		closeRustLinks(attachment.links)
		return
	}

	if err := c.publish(pid, attachment); err != nil {
		_ = c.tracer.bpfObjects.RustCapabilities.Delete(uint32(pid))
		closeRustLinks(attachment.links)
		cause = errors.Join(cause, err)
	} else {
		target.links = attachment.links
		if attachment.capabilities.TaskContext != 0 {
			c.tracer.log.Info("Enabled Tokio task tracking", "pid", pid)
		}
	}

	if errors.Is(cause, rustexec.ErrUnsupportedCompiler) {
		c.tracer.log.Info("Using generic instrumentation for Rust process", "pid", pid, "error", cause)
	} else if cause != nil {
		c.tracer.log.Debug("Rust context propagation unavailable", "pid", pid, "error", cause)
	}
}

func (c *rustController) publish(pid app.PID, attachment rustAttachment) error {
	if attachment.capabilities.TaskContext == 0 {
		return nil
	}

	objects := &c.tracer.bpfObjects
	if err := checkRustLifecycle(pid, attachment.expectedStartTime); err != nil {
		return err
	}

	return objects.RustCapabilities.Put(uint32(pid), attachment.capabilities)
}

func closeRustLinks(links []io.Closer) {
	for _, closer := range links {
		_ = closer.Close()
	}
}

// attach does the slow per-executable work without writing any BPF map.
func (c *rustController) attach(pid app.PID, fi *exec.FileInfo) (rustAttachment, error) {
	expectedStartTime := fi.StartTime()
	if pid != fi.Pid() {
		// Grouped workers share their parent's executable and service FileInfo.
		childStartTime, err := procs.StartTime(pid)
		if err != nil {
			return rustAttachment{}, err
		}
		expectedStartTime = childStartTime
	}

	target, err := fi.OpenExecutable()
	if err != nil {
		return rustAttachment{}, err
	}

	defer target.Close()

	// Replicas and forked workers of one binary reuse its compiler and symbol analysis.
	executable := analyzeRustExecutable(c.executables, target)
	if executable.err != nil {
		return rustAttachment{}, executable.err
	}

	probes := executable.probes
	groups := planRustProbes(probes)
	path := fmt.Sprintf("/proc/self/fd/%d", target.Fd())

	exe, err := link.OpenExecutable(path)
	if err != nil {
		return rustAttachment{}, err
	}

	objects := &c.tracer.bpfObjects
	programs := []struct {
		kind    rustProbeKind
		program *ebpf.Program
		ret     bool
	}{
		{rustTaskPoll, objects.ObiRustTaskPollRet, true},
		{rustTaskHarnessPoll, objects.ObiRustTaskPollRet, true},
		{rustTaskHarnessPoll, objects.ObiRustTaskPoll, false},
		{rustTaskHarnessDealloc, objects.ObiRustTaskDealloc, false},
		{rustTaskNew, objects.ObiRustTaskNew, true},
		{rustTaskRawNew, objects.ObiRustTaskNew, true},
		{rustTaskBind, objects.ObiRustTaskBind, false},
		{rustTaskPublish, objects.ObiRustTaskBind, false},
		{rustTaskSpawn, objects.ObiRustTaskSpawnRet, true},
		{rustTaskSpawn, objects.ObiRustTaskSpawn, false},
		{rustTaskSpawnPublic, objects.ObiRustTaskSpawnRet, true},
		{rustTaskSpawnPublic, objects.ObiRustTaskSpawn, false},
		{rustTaskSchedule, objects.ObiRustTaskSchedule, false},
		{rustTaskScheduleLocal, objects.ObiRustTaskScheduleLocal, false},

		{rustTaskDealloc, objects.ObiRustTaskDealloc, false},

		{rustTaskPoll, objects.ObiRustTaskPoll, false},
	}

	attachAlternative := func(alternative rustProbeAlternative) ([]io.Closer, error) {
		var attached []io.Closer
		for _, probe := range programs {
			addresses := alternative[probe.kind]
			if len(addresses) == 0 {
				continue
			}

			l, err := uprobe.Attach(exe, path, probe.program, uprobe.Options{
				Addresses: addresses, PID: uint32(pid), Return: probe.ret,
			})
			if err != nil {
				return attached, err
			}
			attached = append(attached, l)
		}

		return attached, nil
	}

	links, features, attachErr := attachRustGroups(groups, attachAlternative)

	if attachErr != nil {
		c.tracer.log.Debug("Partial Rust probe attachment", "pid", pid, "error", attachErr)
	}

	capabilities := BpfRustCapabilitiesT{}
	if probes.hasTokio {
		capabilities.TokioRuntime = 1
	}

	if features["task-poll"] && (features["task-create"] || features["task-dealloc"]) {
		capabilities.TaskContext = 1
		if !probes.hasHyper {
			capabilities.ClientContext = 1
		}
	}

	if capabilities.TaskContext == 0 {
		closeRustLinks(links)
		return rustAttachment{}, errors.Join(errors.New("no usable Tokio task probes"), attachErr)
	}

	return rustAttachment{
		links:             links,
		capabilities:      capabilities,
		expectedStartTime: expectedStartTime,
	}, nil
}

// checkRustLifecycle rejects a PID that no longer runs the process discovery saw.
func checkRustLifecycle(pid app.PID, expectedStartTime uint64) error {
	startTime, err := procs.StartTime(pid)
	if err != nil {
		return err
	}

	if startTime != expectedStartTime {
		return errors.New("rust process lifecycle changed during attachment")
	}

	return nil
}

func (c *rustController) block(pid app.PID, fi *exec.FileInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if target := c.targets[pid]; target != nil && (fi == nil || target.lifecycle == fi) {
		c.remove(pid)
	}
}

func (c *rustController) remove(pid app.PID) {
	if c.tracer.bpfObjects.RustCapabilities != nil {
		_ = c.tracer.bpfObjects.RustCapabilities.Delete(uint32(pid))
	}

	for _, closer := range c.targets[pid].links {
		_ = closer.Close()
	}

	delete(c.targets, pid)
}

// Close waits for attachments in progress: their commits close the probes they
// attached, before the tracer closes the BPF programs those probes use.
func (c *rustController) Close() error {
	c.mu.Lock()
	c.closed = true

	for pid := range c.targets {
		c.remove(pid)
	}
	c.mu.Unlock()

	c.attaching.Wait()

	return nil
}

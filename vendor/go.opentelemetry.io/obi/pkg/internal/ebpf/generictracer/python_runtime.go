// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	appruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	cpythonruntime "go.opentelemetry.io/obi/pkg/internal/cpython/runtime"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

var nextPythonRuntimeGeneration atomic.Uint64

// pythonRuntimeTargetResolver isolates process-specific ELF analysis for tests.
type pythonRuntimeTargetResolver interface {
	Resolve(context.Context, app.PID, uint64) (*cpythonruntime.MetricTarget, error)
}

// pythonRuntimeMap is the map subset used by the lifecycle controller.
type pythonRuntimeMap interface {
	Put(key, value any) error
	Lookup(key, valueOut any) error
	Delete(key any) error
}

// pythonRuntimeLifecycle tracks one exact lifetime of one Python PID.
type pythonRuntimeLifecycle struct {
	pid           app.PID
	ns            uint32
	startTime     uint64
	generation    uint64
	lifecycle     *exec.FileInfo
	serviceSource *exec.FileInfo
	key           BpfPidInfo
	link          io.Closer
	cancel        context.CancelFunc
}

// pythonRuntimeController owns Python probe links and their BPF map state.
type pythonRuntimeController struct {
	tracer      *Tracer
	resolver    pythonRuntimeTargetResolver
	targetMap   pythonRuntimeMap
	snapshotMap pythonRuntimeMap
	attach      func(*cpythonruntime.MetricTarget, *ebpf.Program, int) (io.Closer, error)
	startTime   func(app.PID) (uint64, error)

	mu      sync.Mutex
	targets map[app.PID]*pythonRuntimeLifecycle
	closed  bool
}

func newPythonRuntimeController(tracer *Tracer) *pythonRuntimeController {
	if tracer == nil || tracer.cfg == nil {
		return nil
	}
	return &pythonRuntimeController{
		tracer:    tracer,
		resolver:  cpythonruntime.NewResolver(),
		targets:   map[app.PID]*pythonRuntimeLifecycle{},
		attach:    attachPythonRuntimeTarget,
		startTime: cpythonruntime.ProcessStartTime,
	}
}

// newPythonRuntimeGeneration returns a nonzero identity for stale-data checks.
func newPythonRuntimeGeneration() uint64 {
	for {
		if generation := nextPythonRuntimeGeneration.Add(1); generation != 0 {
			return generation
		}
	}
}

// allow starts one asynchronous setup for an exact process lifecycle.
func (c *pythonRuntimeController) allow(
	pid app.PID,
	ns uint32,
	lifecycle *exec.FileInfo,
	serviceSource *exec.FileInfo,
) {
	if c == nil || !pythonRuntimeEligible(pid, lifecycle, serviceSource) {
		return
	}
	startTime := lifecycle.StartTime()
	if startTime == 0 {
		return
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	if existing := c.targets[pid]; existing != nil {
		if existing.lifecycle == lifecycle && existing.startTime == startTime {
			c.mu.Unlock()
			return
		}
		c.cleanupLocked(existing)
		delete(c.targets, pid)
	}

	generation := newPythonRuntimeGeneration()
	ctx, cancel := context.WithCancel(context.Background())
	target := &pythonRuntimeLifecycle{
		pid:           pid,
		ns:            ns,
		startTime:     startTime,
		generation:    generation,
		lifecycle:     lifecycle,
		serviceSource: serviceSource,
		cancel:        cancel,
	}
	lifecycle.SetRuntimeMetricServiceSource(serviceSource)
	lifecycle.SetRuntimeMetricGeneration(pid, generation)
	if serviceSource != lifecycle {
		serviceSource.SetRuntimeMetricGeneration(pid, generation)
	}
	c.targets[pid] = target
	c.mu.Unlock()

	go c.resolveAndAttach(ctx, target)
}

// pythonRuntimeEligible applies the service feature and export gates.
func pythonRuntimeEligible(pid app.PID, lifecycle, serviceSource *exec.FileInfo) bool {
	if pid <= 0 || lifecycle == nil || serviceSource == nil ||
		serviceSource.SDKLanguage() != svc.InstrumentablePython {
		return false
	}
	service := serviceSource.ServiceAttrs()
	return service.Features.AppRuntime() && service.ExportModes.CanExportMetrics()
}

// resolveAndAttach resolves one process lifecycle, then commits its map and link state.
func (c *pythonRuntimeController) resolveAndAttach(ctx context.Context, target *pythonRuntimeLifecycle) {
	metricTarget, err := c.resolver.Resolve(ctx, target.pid, target.startTime)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			c.tracer.log.Debug("Python runtime metrics target resolution failed",
				"pid", target.pid, "error", err)
		}
		c.removeUnattached(target)
		return
	}
	defer metricTarget.Close()

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || ctx.Err() != nil || c.targets[target.pid] != target {
		return
	}
	key, err := pythonRuntimePIDInfo(target.pid, target.ns)
	if err != nil {
		c.tracer.log.Debug("Python runtime metrics PID key lookup failed",
			"pid", target.pid, "error", err)
		delete(c.targets, target.pid)
		return
	}
	target.key = key
	targets, snapshots := c.maps()
	if targets == nil || snapshots == nil || c.tracer.bpfObjects.ObiUprobePythonGcDone == nil {
		delete(c.targets, target.pid)
		return
	}

	_ = targets.Delete(key)
	_ = snapshots.Delete(key)
	value := BpfPythonRuntimeMetricTarget{
		RuntimeAddr:             metricTarget.RuntimeAddress,
		Generation:              target.generation,
		RuntimeFinalizing:       metricTarget.RuntimeFinalizing,
		RuntimeInterpretersMain: metricTarget.RuntimeInterpretersMain,
		InterpreterGc:           metricTarget.InterpreterGC,
		GcGenerationStats:       metricTarget.GCGenerationStats,
	}
	if err := targets.Put(key, value); err != nil {
		c.tracer.log.Warn("Python runtime metrics target map update failed",
			"pid", target.pid, "error", err)
		delete(c.targets, target.pid)
		return
	}

	attached, err := c.attach(
		metricTarget, c.tracer.bpfObjects.ObiUprobePythonGcDone, int(target.pid))
	if err != nil {
		_ = targets.Delete(key)
		_ = snapshots.Delete(key)
		delete(c.targets, target.pid)
		c.tracer.log.Warn("Python runtime metrics probe attachment failed",
			"pid", target.pid, "probe", metricTarget.PrimaryProbe.Kind, "error", err)
		return
	}
	currentStartTime, err := c.startTime(target.pid)
	if err != nil || currentStartTime != target.startTime {
		_ = attached.Close()
		_ = targets.Delete(key)
		_ = snapshots.Delete(key)
		delete(c.targets, target.pid)
		return
	}
	target.link = attached
	c.tracer.log.Debug("Python runtime metrics attached",
		"pid", target.pid,
		"probe", metricTarget.PrimaryProbe.Kind,
		"offset", fmt.Sprintf("%#x", metricTarget.PrimaryProbe.FileOffset))
}

// attachPythonRuntimeTarget attaches to the stable mapped object and safe fallback.
func attachPythonRuntimeTarget(target *cpythonruntime.MetricTarget, program *ebpf.Program, pid int) (io.Closer, error) {
	if target == nil || program == nil || target.AttachmentPath() == "" {
		return nil, errors.New("incomplete Python runtime metric target")
	}
	executable, err := link.OpenExecutable(target.AttachmentPath())
	if err != nil {
		return nil, err
	}
	attached, err := attachPythonRuntimeProbe(executable, program, pid, target.PrimaryProbe)
	if err == nil {
		return attached, nil
	}
	if target.FallbackProbe == nil {
		return nil, err
	}
	fallback, fallbackErr := attachPythonRuntimeProbe(executable, program, pid, *target.FallbackProbe)
	if fallbackErr != nil {
		return nil, errors.Join(err, fallbackErr)
	}
	return fallback, nil
}

// attachPythonRuntimeProbe selects an entry or return probe at a raw offset.
func attachPythonRuntimeProbe(
	executable *link.Executable,
	program *ebpf.Program,
	pid int,
	probe cpythonruntime.GCCompletionProbe,
) (link.Link, error) {
	options, returnProbe, err := pythonRuntimeUprobeOptions(pid, probe)
	if err != nil {
		return nil, err
	}
	if !returnProbe {
		return executable.Uprobe("", program, options)
	}
	return executable.Uretprobe("", program, options)
}

// pythonRuntimeUprobeOptions converts a resolved GC completion probe into link options.
func pythonRuntimeUprobeOptions(
	pid int,
	probe cpythonruntime.GCCompletionProbe,
) (*link.UprobeOptions, bool, error) {
	options := &link.UprobeOptions{Address: probe.FileOffset, PID: pid}
	switch probe.Kind {
	case cpythonruntime.GCCompletionProbeUSDT:
		options.RefCtrOffset = probe.SemaphoreOffset
		return options, false, nil
	case cpythonruntime.GCCompletionProbePrivateReturn:
		return options, true, nil
	default:
		return nil, false, errors.New("unknown Python runtime GC completion probe")
	}
}

// removeUnattached removes only the lifecycle that failed asynchronous setup.
func (c *pythonRuntimeController) removeUnattached(target *pythonRuntimeLifecycle) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.targets[target.pid] == target && target.link == nil {
		delete(c.targets, target.pid)
	}
}

// block drains the final snapshot before it removes one lifecycle.
func (c *pythonRuntimeController) block(
	pid app.PID,
	ns uint32,
	lifecycle *exec.FileInfo,
) {
	if c == nil || lifecycle == nil {
		return
	}
	c.mu.Lock()
	target := c.targets[pid]
	if target == nil || target.ns != ns || target.lifecycle != lifecycle ||
		target.startTime != lifecycle.StartTime() ||
		target.generation != lifecycle.RuntimeMetricGeneration(pid) {
		c.mu.Unlock()
		return
	}
	target.cancel()
	if target.link != nil {
		_ = target.link.Close()
		target.link = nil
	}

	final := appruntime.PythonRuntimeMetricFinal{
		PID: pid, Generation: target.generation, Time: time.Now(),
	}
	targets, snapshots := c.maps()
	if snapshots != nil {
		var raw BpfPythonRuntimeMetricSnapshot
		if err := snapshots.Lookup(target.key, &raw); err == nil && raw.Generation == target.generation {
			final.HasValue = true
			for generation := range final.Generations {
				final.Generations[generation] = appruntime.PythonGCGenerationMetrics{
					Collections:          raw.Generations[generation].Collections,
					CollectedObjects:     raw.Generations[generation].Collected,
					UncollectableObjects: raw.Generations[generation].Uncollectable,
				}
			}
		}
	}
	deletePythonRuntimeMapEntries(targets, snapshots, target.key)
	delete(c.targets, pid)
	c.mu.Unlock()

	if target.serviceSource != nil {
		target.serviceSource.SetPythonRuntimeMetricFinal(final)
	}
}

// close cancels pending setup and releases every active process target.
func (c *pythonRuntimeController) close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	for pid, target := range c.targets {
		c.cleanupLocked(target)
		delete(c.targets, pid)
	}
}

// cleanupLocked releases one target while the controller lock is held.
func (c *pythonRuntimeController) cleanupLocked(target *pythonRuntimeLifecycle) {
	if target == nil {
		return
	}
	target.cancel()
	if target.link != nil {
		_ = target.link.Close()
		target.link = nil
	}
	targets, snapshots := c.maps()
	deletePythonRuntimeMapEntries(targets, snapshots, target.key)
}

// deletePythonRuntimeMapEntries removes both halves of one BPF process state.
func deletePythonRuntimeMapEntries(targets, snapshots pythonRuntimeMap, key BpfPidInfo) {
	if targets != nil {
		_ = targets.Delete(key)
	}
	if snapshots != nil {
		_ = snapshots.Delete(key)
	}
}

// maps returns injected test maps or the loaded BPF maps.
func (c *pythonRuntimeController) maps() (pythonRuntimeMap, pythonRuntimeMap) {
	if c == nil || c.tracer == nil {
		return nil, nil
	}
	if c.targetMap != nil || c.snapshotMap != nil {
		return c.targetMap, c.snapshotMap
	}
	return c.tracer.bpfObjects.PythonRuntimeMetricTargets,
		c.tracer.bpfObjects.PythonRuntimeMetricSnapshots
}

// pythonRuntimePIDInfo builds the same namespace-aware key as task_pid in BPF.
func pythonRuntimePIDInfo(pid app.PID, ns uint32) (BpfPidInfo, error) {
	key := BpfPidInfo{HostPid: uint32(pid), UserPid: uint32(pid), Ns: ns}
	pids, err := procs.FindNamespacedPids(pid)
	if err != nil {
		return BpfPidInfo{}, fmt.Errorf("reading namespaced PIDs: %w", err)
	}
	if len(pids) != 0 {
		key.HostPid = uint32(pids[0])
		key.UserPid = uint32(pids[len(pids)-1])
	}
	return key, nil
}

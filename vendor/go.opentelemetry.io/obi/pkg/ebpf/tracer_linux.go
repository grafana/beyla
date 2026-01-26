// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	common "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

const PinInternal = ebpf.PinType(100)

func ptlog() *slog.Logger { return slog.With("component", "ebpf.ProcessTracer") }

type instrumenter struct {
	offsets     *goexec.Offsets
	exe         *link.Executable
	closables   []io.Closer
	modules     map[uint64]struct{}
	metrics     imetrics.Reporter
	processName string
}

func roundToNearestMultiple(x, n uint32) uint32 {
	if x < n {
		return n
	}

	if x%n == 0 {
		return x
	}

	return (x + n/2) / n * n
}

// RingBuf map types must be a multiple of os.Getpagesize()
func alignMaxEntriesIfRingBuf(m *ebpf.MapSpec) {
	if m.Type == ebpf.RingBuf {
		m.MaxEntries = roundToNearestMultiple(m.MaxEntries, uint32(os.Getpagesize()))
	}
}

// sets up internal maps and ensures sane max entries values
func resolveMaps(eventContext *common.EBPFEventContext, spec *ebpf.CollectionSpec) (*ebpf.CollectionOptions, error) {
	collOpts := ebpf.CollectionOptions{MapReplacements: map[string]*ebpf.Map{}}

	eventContext.MapsLock.Lock()
	defer eventContext.MapsLock.Unlock()

	for k, v := range spec.Maps {
		alignMaxEntriesIfRingBuf(v)

		if v.Pinning != PinInternal {
			continue
		}

		v.Pinning = ebpf.PinNone
		internalMap := eventContext.EBPFMaps[k]

		var err error

		if internalMap == nil {
			internalMap, err = ebpf.NewMap(v)
			if err != nil {
				return nil, fmt.Errorf("failed to load shared map: %w", err)
			}

			eventContext.EBPFMaps[k] = internalMap
			runtime.SetFinalizer(internalMap, (*ebpf.Map).Close)
		}

		collOpts.MapReplacements[k] = internalMap
	}

	return &collOpts, nil
}

func unloadInternalMaps(eventContext *common.EBPFEventContext) {
	eventContext.MapsLock.Lock()
	defer eventContext.MapsLock.Unlock()

	for _, v := range eventContext.EBPFMaps {
		v.Close()
	}

	eventContext.EBPFMaps = make(map[string]*ebpf.Map)
}

func NewProcessTracer(tracerType ProcessTracerType, programs []Tracer, shutdownTimeout time.Duration, metrics imetrics.Reporter) *ProcessTracer {
	return &ProcessTracer{
		Programs:        programs,
		Type:            tracerType,
		Instrumentables: map[uint64]*instrumenter{},
		shutdownTimeout: shutdownTimeout,
		metrics:         metrics,
	}
}

type tracerInstance struct {
	implType string
	done     atomic.Bool
}

func (pt *ProcessTracer) Run(ctx context.Context, ebpfEventContext *common.EBPFEventContext, out *msg.Queue[[]request.Span]) {
	pt.log = ptlog().With("type", pt.Type)

	pt.log.Debug("starting process tracer")
	// Searches for traceable functions
	trcrs := pt.Programs
	wg := sync.WaitGroup{}
	runningTracers := make([]tracerInstance, 0, len(trcrs))
	for i := range trcrs {
		idx := i
		t := trcrs[idx]
		wg.Add(1)
		runningTracers = append(runningTracers, tracerInstance{
			implType: reflect.TypeOf(t).String(),
		})
		go func() {
			defer wg.Done()
			t.Run(ctx, ebpfEventContext, out)
			runningTracers[idx].done.Store(true)
		}()
	}

	<-ctx.Done()

	tracersEnded := make(chan struct{})
	go func() {
		wg.Wait()
		close(tracersEnded)
	}()
	unloadInternalMaps(ebpfEventContext)

	hasWarned := false
	for {
		select {
		// notifyng before OBI times out on finish
		case <-time.After(3 * pt.shutdownTimeout / 4):
			pt.log.Warn("some process tracers did not finish", "tracers", runningTracers)
			hasWarned = true
		case <-tracersEnded:
			if hasWarned {
				pt.log.Info("all process tracers finished")
			}
			return
		}
	}
}

func (pt *ProcessTracer) loadSpec(p Tracer) (*ebpf.CollectionSpec, error) {
	spec, err := p.Load()
	if err != nil {
		return nil, fmt.Errorf("loading eBPF program: %w", err)
	}
	if err := ebpfconvenience.RewriteConstants(spec, p.Constants()); err != nil {
		return nil, fmt.Errorf("rewriting BPF constants definition: %w", err)
	}

	return spec, nil
}

func (pt *ProcessTracer) loadAndAssign(eventContext *common.EBPFEventContext, p Tracer) error {
	spec, err := pt.loadSpec(p)
	if err != nil {
		return err
	}

	collOpts, err := resolveMaps(eventContext, spec)
	if err != nil {
		return err
	}

	collOpts.Programs = ebpf.ProgramOptions{LogSizeStart: 640 * 1024}

	return spec.LoadAndAssign(p.BpfObjects(), collOpts)
}

func (pt *ProcessTracer) loadTracer(eventContext *common.EBPFEventContext, p Tracer, log *slog.Logger) error {
	plog := log.With("program", reflect.TypeOf(p))
	plog.Debug("loading eBPF program", "type", pt.Type)

	err := pt.loadAndAssign(eventContext, p)

	if err != nil && (strings.Contains(err.Error(), "unknown func bpf_probe_write_user") ||
		strings.Contains(err.Error(), "cannot use helper bpf_probe_write_user")) {
		plog.Warn("Failed to enable Go write memory distributed tracing context-propagation on a " +
			"Linux Kernel without write memory support. " +
			"To avoid seeing this message, please ensure you have correctly mounted /sys/kernel/security. " +
			"and ensure beyla has the SYS_ADMIN linux capability. " +
			"For more details set OTEL_EBPF_LOG_LEVEL=DEBUG.")

		common.IntegrityModeOverride = true
		err = pt.loadAndAssign(eventContext, p)
	}

	if err != nil {
		printVerifierErrorInfo(err)
		return fmt.Errorf("loading and assigning BPF objects: %w", err)
	}

	// Setup any tail call jump tables
	p.SetupTailCalls()

	i := instrumenter{} // dummy instrumenter to setup the kprobes, socket filters and tracepoint probes

	// Kprobes to be used for native instrumentation points
	if err := i.kprobes(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	// Tracepoints support
	if err := i.tracepoints(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	// Sock filters support
	if err := i.sockfilters(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	// Sock_msg support
	if err := i.sockmsgs(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	// Sockops support
	if err := i.sockops(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	if err := i.iters(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	return nil
}

func (pt *ProcessTracer) loadTracers(eventContext *common.EBPFEventContext) error {
	eventContext.LoadLock.Lock()
	defer eventContext.LoadLock.Unlock()

	log := ptlog()

	loadedPrograms := make([]Tracer, 0, len(pt.Programs))

	for _, p := range pt.Programs {
		if err := pt.loadTracer(eventContext, p, log); err != nil {
			log.Warn("couldn't load tracer", "error", err, "required", p.Required())
			if p.Required() {
				return err
			}
		} else {
			loadedPrograms = append(loadedPrograms, p)
		}
	}

	pt.Programs = loadedPrograms

	btf.FlushKernelSpec()

	return nil
}

func (pt *ProcessTracer) Init(eventContext *common.EBPFEventContext) error {
	return pt.loadTracers(eventContext)
}

func (pt *ProcessTracer) NewExecutableInstance(ie *Instrumentable) error {
	if i, ok := pt.Instrumentables[ie.FileInfo.Ino]; ok {
		for _, p := range pt.Programs {
			p.ProcessBinary(ie.FileInfo)
			// Uprobes to be used for native module instrumentation points
			if err := i.uprobes(ie.FileInfo.Pid, p); err != nil {
				printVerifierErrorInfo(err)
				return err
			}
		}
	} else {
		pt.log.Warn("Attempted to update non-existent tracer", "path", ie.FileInfo.CmdExePath, "pid", ie.FileInfo.Pid)
	}

	return nil
}

func (pt *ProcessTracer) NewExecutable(exe *link.Executable, ie *Instrumentable) error {
	i := instrumenter{
		exe:         exe,
		offsets:     ie.Offsets, // this is needed for the function offsets, not fields
		modules:     map[uint64]struct{}{},
		metrics:     pt.metrics,
		processName: ie.FileInfo.CmdExePath,
	}

	for _, p := range pt.Programs {
		p.RegisterOffsets(ie.FileInfo, ie.Offsets)

		// Go style Uprobes
		if err := i.goprobes(p); err != nil {
			printVerifierErrorInfo(err)
			return err
		}

		// Uprobes to be used for native module instrumentation points
		if err := i.uprobes(ie.FileInfo.Pid, p); err != nil {
			printVerifierErrorInfo(err)
			return err
		}
	}

	pt.Instrumentables[ie.FileInfo.Ino] = &i

	return nil
}

func (pt *ProcessTracer) UnlinkExecutable(info *exec.FileInfo) {
	if i, ok := pt.Instrumentables[info.Ino]; ok {
		for _, c := range i.closables {
			if err := c.Close(); err != nil {
				pt.log.Debug("Unable to close on unlink", "closable", c)
			}
		}
		for ino := range i.modules {
			for _, p := range pt.Programs {
				p.UnlinkInstrumentedLib(ino)
			}
		}
		delete(pt.Instrumentables, info.Ino)
	} else {
		pt.log.Warn("Unable to find executable to unlink",
			"path", info.CmdExePath,
			"pid", info.Pid,
			"inode", info.Ino)
	}
}

func printVerifierErrorInfo(err error) {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		_, _ = fmt.Fprintf(os.Stderr, "Error Log:\n %v\n", strings.Join(ve.Log, "\n"))
	}
}

func RunUtilityTracer(ctx context.Context, eventContext *common.EBPFEventContext, p UtilityTracer) error {
	i := instrumenter{}
	plog := ptlog()
	plog.Debug("loading independent eBPF program")
	spec, err := p.Load()
	if err != nil {
		return fmt.Errorf("loading eBPF program: %w", err)
	}

	collOpts, err := resolveMaps(eventContext, spec)
	if err != nil {
		return err
	}

	if err := spec.LoadAndAssign(p.BpfObjects(), collOpts); err != nil {
		printVerifierErrorInfo(err)
		return fmt.Errorf("loading and assigning BPF objects: %w", err)
	}

	if err := i.kprobes(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	if err := i.tracepoints(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	go p.Run(ctx)

	btf.FlushKernelSpec()

	return nil
}

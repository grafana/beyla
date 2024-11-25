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

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"

	"github.com/grafana/beyla/pkg/beyla"
	common "github.com/grafana/beyla/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/pkg/internal/exec"
	"github.com/grafana/beyla/pkg/internal/goexec"
	"github.com/grafana/beyla/pkg/internal/request"
)

const PinInternal = ebpf.PinType(100)

var loadMux sync.Mutex

var internalMaps = make(map[string]*ebpf.Map)
var internalMapsMux sync.Mutex

func ptlog() *slog.Logger { return slog.With("component", "ebpf.ProcessTracer") }

type instrumenter struct {
	offsets   *goexec.Offsets
	exe       *link.Executable
	closables []io.Closer
	modules   map[uint64]struct{}
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
func resolveMaps(spec *ebpf.CollectionSpec) (*ebpf.CollectionOptions, error) {
	collOpts := ebpf.CollectionOptions{MapReplacements: map[string]*ebpf.Map{}}

	internalMapsMux.Lock()
	defer internalMapsMux.Unlock()

	for k, v := range spec.Maps {
		alignMaxEntriesIfRingBuf(v)

		if v.Pinning != PinInternal {
			continue
		}

		v.Pinning = ebpf.PinNone
		internalMap := internalMaps[k]

		var err error

		if internalMap == nil {
			internalMap, err = ebpf.NewMap(v)

			if err != nil {
				return nil, fmt.Errorf("failed to load shared map: %w", err)
			}

			internalMaps[k] = internalMap
			runtime.SetFinalizer(internalMap, (*ebpf.Map).Close)
		}

		collOpts.MapReplacements[k] = internalMap
	}

	return &collOpts, nil
}

func NewProcessTracer(cfg *beyla.Config, tracerType ProcessTracerType, programs []Tracer) *ProcessTracer {
	return &ProcessTracer{
		Programs:        programs,
		SystemWide:      cfg.Discovery.SystemWide,
		Type:            tracerType,
		Instrumentables: map[uint64]*instrumenter{},
	}
}

func (pt *ProcessTracer) Run(ctx context.Context, out chan<- []request.Span) {
	pt.log = ptlog().With("type", pt.Type)

	pt.log.Debug("starting process tracer")
	// Searches for traceable functions
	trcrs := pt.Programs

	wg := sync.WaitGroup{}

	for _, t := range trcrs {
		wg.Add(1)
		go func() {
			t.Run(ctx, out)
			wg.Done()
		}()
	}

	<-ctx.Done()

	wg.Wait()
}

func (pt *ProcessTracer) loadSpec(p Tracer) (*ebpf.CollectionSpec, error) {
	spec, err := p.Load()
	if err != nil {
		return nil, fmt.Errorf("loading eBPF program: %w", err)
	}
	if err := spec.RewriteConstants(p.Constants()); err != nil {
		return nil, fmt.Errorf("rewriting BPF constants definition: %w", err)
	}

	return spec, nil
}

func (pt *ProcessTracer) loadAndAssign(p Tracer) error {
	spec, err := pt.loadSpec(p)

	if err != nil {
		return err
	}

	collOpts, err := resolveMaps(spec)

	if err != nil {
		return err
	}

	collOpts.Programs = ebpf.ProgramOptions{LogSize: 640 * 1024}

	return spec.LoadAndAssign(p.BpfObjects(), collOpts)
}

func (pt *ProcessTracer) loadTracer(p Tracer, log *slog.Logger) error {
	plog := log.With("program", reflect.TypeOf(p))
	plog.Debug("loading eBPF program", "type", pt.Type)

	err := pt.loadAndAssign(p)

	if err != nil && strings.Contains(err.Error(), "unknown func bpf_probe_write_user") {
		plog.Warn("Failed to enable distributed tracing context-propagation on a " +
			"Linux Kernel without write memory support. " +
			"To avoid seeing this message, please ensure you have correctly mounted /sys/kernel/security. " +
			"and ensure beyla has the SYS_ADMIN linux capability" +
			"For more details set BEYLA_LOG_LEVEL=DEBUG.")

		common.IntegrityModeOverride = true
		err = pt.loadAndAssign(p)
	}

	if err != nil {
		printVerifierErrorInfo(err)
		return fmt.Errorf("loading and assigning BPF objects: %w", err)
	}

	// Setup any tail call jump tables
	p.SetupTailCalls()

	// Setup any traffic control probes
	p.SetupTC()

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

	return nil
}

func (pt *ProcessTracer) loadTracers() error {
	loadMux.Lock()
	defer loadMux.Unlock()

	var log = ptlog()

	for _, p := range pt.Programs {
		if err := pt.loadTracer(p, log); err != nil {
			return err
		}
	}

	btf.FlushKernelSpec()

	return nil
}

func (pt *ProcessTracer) Init() error {
	return pt.loadTracers()
}

func (pt *ProcessTracer) NewExecutableInstance(ie *Instrumentable) error {
	if i, ok := pt.Instrumentables[ie.FileInfo.Ino]; ok {
		for _, p := range pt.Programs {
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
		exe:     exe,
		offsets: ie.Offsets, // this is needed for the function offsets, not fields
		modules: map[uint64]struct{}{},
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
		pt.log.Warn("Unable to find executable to unlink", "info", info)
	}
}

func printVerifierErrorInfo(err error) {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		_, _ = fmt.Fprintf(os.Stderr, "Error Log:\n %v\n", strings.Join(ve.Log, "\n"))
	}
}

func RunUtilityTracer(p UtilityTracer) error {
	i := instrumenter{}
	plog := ptlog()
	plog.Debug("loading independent eBPF program")
	spec, err := p.Load()
	if err != nil {
		return fmt.Errorf("loading eBPF program: %w", err)
	}

	collOpts, err := resolveMaps(spec)
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

	go p.Run(context.Background())

	btf.FlushKernelSpec()

	return nil
}

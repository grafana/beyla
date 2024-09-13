package ebpf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"

	common "github.com/grafana/beyla/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/pkg/internal/request"
)

var loadMux sync.Mutex

func ptlog() *slog.Logger { return slog.With("component", "ebpf.ProcessTracer") }

func (pt *ProcessTracer) Run(ctx context.Context, out chan<- []request.Span) {
	pt.log = ptlog().With("type", pt.Type)

	pt.log.Debug("starting process tracer")
	// Searches for traceable functions
	trcrs := pt.Programs

	for _, t := range trcrs {
		go t.Run(ctx, out)
	}
	go func() {
		<-ctx.Done()
	}()
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

func (pt *ProcessTracer) loadTracers() error {
	loadMux.Lock()
	defer loadMux.Unlock()

	var log = ptlog()

	for _, p := range pt.Programs {
		plog := log.With("program", reflect.TypeOf(p))
		plog.Debug("loading eBPF program", "PinPath", pt.PinPath, "type", pt.Type)
		spec, err := pt.loadSpec(p)
		if err != nil {
			return err
		}
		if err := spec.LoadAndAssign(p.BpfObjects(), &ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{LogSize: 640 * 1024},
			Maps: ebpf.MapOptions{
				PinPath: pt.PinPath,
			}}); err != nil {
			if strings.Contains(err.Error(), "unknown func bpf_probe_write_user") {
				plog.Warn("Failed to enable distributed tracing context-propagation on a Linux Kernel without write memory support. " +
					"To avoid seeing this message, please ensure you have correctly mounted /sys/kernel/security. " +
					"and ensure beyla has the SYS_ADMIN linux capability" +
					"For more details set BEYLA_LOG_LEVEL=DEBUG.")

				common.IntegrityModeOverride = true
				spec, err = pt.loadSpec(p)
				if err == nil {
					err = spec.LoadAndAssign(p.BpfObjects(), &ebpf.CollectionOptions{
						Programs: ebpf.ProgramOptions{LogSize: 640 * 1024},
						Maps: ebpf.MapOptions{
							PinPath: pt.PinPath,
						}})
				}
			}
			if err != nil {
				printVerifierErrorInfo(err)
				return fmt.Errorf("loading and assigning BPF objects: %w", err)
			}
		}

		// Setup any tail call jump tables
		p.SetupTailCalls()

		// Setup any traffic control probes
		p.SetupTC()
	}

	btf.FlushKernelSpec()

	return nil
}

func (pt *ProcessTracer) Init() error {
	return pt.loadTracers()
}

func (pt *ProcessTracer) NewExecutableForTracer(exe *link.Executable, ie *Instrumentable) error {
	i := instrumenter{
		exe:     exe,
		offsets: ie.Offsets,
	}

	for _, p := range pt.Programs {
		// Go style Uprobes
		if err := i.goprobes(p); err != nil {
			printVerifierErrorInfo(err)
			return err
		}

		// Kprobes to be used for native instrumentation points
		if err := i.kprobes(p); err != nil {
			printVerifierErrorInfo(err)
			return err
		}

		// Uprobes to be used for native module instrumentation points
		if err := i.uprobes(ie.FileInfo.Pid, p); err != nil {
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
	}

	return nil
}

func printVerifierErrorInfo(err error) {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		_, _ = fmt.Fprintf(os.Stderr, "Error Log:\n %v\n", strings.Join(ve.Log, "\n"))
	}
}

func RunUtilityTracer(p UtilityTracer, pinPath string) error {
	i := instrumenter{}
	plog := ptlog()
	plog.Debug("loading independent eBPF program")
	spec, err := p.Load()
	if err != nil {
		return fmt.Errorf("loading eBPF program: %w", err)
	}

	if err := spec.LoadAndAssign(p.BpfObjects(), &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinPath,
		}}); err != nil {
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

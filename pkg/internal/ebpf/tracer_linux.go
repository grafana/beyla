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

	common "github.com/grafana/beyla/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/pkg/internal/request"
)

var loadMux sync.Mutex

func ptlog() *slog.Logger { return slog.With("component", "ebpf.ProcessTracer") }

func (pt *ProcessTracer) Run(ctx context.Context, out chan<- []request.Span) {
	pt.log = ptlog().With("path", pt.ELFInfo.CmdExePath, "pid", pt.ELFInfo.Pid)

	pt.log.Debug("starting process tracer")
	// Searches for traceable functions
	trcrs, err := pt.tracers()
	if err != nil {
		pt.log.Error("couldn't trace process. Stopping process tracer", "error", err)
		return
	}

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
	if err := spec.RewriteConstants(p.Constants(pt.ELFInfo, pt.Goffsets)); err != nil {
		return nil, fmt.Errorf("rewriting BPF constants definition: %w", err)
	}

	return spec, nil
}

// tracers returns Tracer implementer for each discovered eBPF traceable source: GRPC, HTTP...
func (pt *ProcessTracer) tracers() ([]Tracer, error) {
	loadMux.Lock()
	defer loadMux.Unlock()
	var log = ptlog()

	// tracerFuncs contains the eBPF Programs (HTTP, GRPC tracers...)
	var tracers []Tracer

	for _, p := range pt.Programs {
		plog := log.With("program", reflect.TypeOf(p))
		plog.Debug("loading eBPF program", "PinPath", pt.PinPath, "pid", pt.ELFInfo.Pid, "cmd", pt.ELFInfo.CmdExePath)
		spec, err := pt.loadSpec(p)
		if err != nil {
			return nil, err
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
				return nil, fmt.Errorf("loading and assigning BPF objects: %w", err)
			}
		}

		// Setup any tail call jump tables
		p.SetupTailCalls()

		i := instrumenter{
			exe:     pt.Exe,
			offsets: pt.Goffsets,
		}

		// Go style Uprobes
		if err := i.goprobes(p); err != nil {
			printVerifierErrorInfo(err)
			return nil, err
		}

		// Kprobes to be used for native instrumentation points
		if err := i.kprobes(p); err != nil {
			printVerifierErrorInfo(err)
			return nil, err
		}

		// Uprobes to be used for native module instrumentation points
		if err := i.uprobes(pt.ELFInfo.Pid, p); err != nil {
			printVerifierErrorInfo(err)
			return nil, err
		}

		// Tracepoints support
		if err := i.tracepoints(p); err != nil {
			printVerifierErrorInfo(err)
			return nil, err
		}

		// Sock filters support
		if err := i.sockfilters(p); err != nil {
			printVerifierErrorInfo(err)
			return nil, err
		}

		tracers = append(tracers, p)
	}

	return tracers, nil
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

	return nil
}

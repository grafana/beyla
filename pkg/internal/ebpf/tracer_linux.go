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
	service := pt.ELFInfo.Service
	// If the user does not override the service name via configuration
	// the service name is the name of the found executable
	// Unless the case of system-wide tracing, where the name of the
	// executable will be dynamically set for each traced http request call.
	if service.Name == "" && !pt.SystemWide {
		service.Name = pt.ELFInfo.ExecutableName()
		// we mark the service ID as automatically named in case we want to look,
		// in later stages of the pipeline, for better automatic service name
		service.AutoName = true
	}

	for _, t := range trcrs {
		go t.Run(ctx, out, service)
	}
	go func() {
		<-ctx.Done()
	}()
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
		spec, err := p.Load()
		if err != nil {
			return nil, fmt.Errorf("loading eBPF program: %w", err)
		}
		if err := spec.RewriteConstants(p.Constants(pt.ELFInfo, pt.Goffsets)); err != nil {
			return nil, fmt.Errorf("rewriting BPF constants definition: %w", err)
		}
		if err := spec.LoadAndAssign(p.BpfObjects(), &ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{
				PinPath: pt.PinPath,
			}}); err != nil {
			printVerifierErrorInfo(err)
			return nil, fmt.Errorf("loading and assigning BPF objects: %w", err)
		}
		i := instrumenter{
			exe:     pt.Exe,
			offsets: pt.Goffsets,
		}

		//Go style Uprobes
		if err := i.goprobes(p); err != nil {
			printVerifierErrorInfo(err)
			return nil, err
		}

		//Kprobes to be used for native instrumentation points
		if err := i.kprobes(p); err != nil {
			printVerifierErrorInfo(err)
			return nil, err
		}

		//Uprobes to be used for native module instrumentation points
		if err := i.uprobes(pt.ELFInfo.Pid, p); err != nil {
			printVerifierErrorInfo(err)
			return nil, err
		}

		//Sock filters support
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

	go p.Run(context.Background())

	return nil
}

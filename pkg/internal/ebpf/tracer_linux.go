package ebpf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
)

func ptlog() *slog.Logger { return slog.With("component", "ebpf.ProcessTracer") }

func (pt *ProcessTracer) Run(ctx context.Context, out chan<- []request.Span) {
	if err := pt.init(); err != nil {
		pt.log.Error("cant start process tracer. Stopping it", "error", err)
		return
	}
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
	}
	// run each tracer program
	for _, t := range trcrs {
		go t.Run(ctx, out, service)
	}
	go func() {
		<-ctx.Done()
		pt.close()
	}()
}

func (pt *ProcessTracer) init() error {
	pt.log = ptlog().With("path", pt.ELFInfo.CmdExePath, "pid", pt.ELFInfo.Pid)
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memory lock: %w", err)
	}
	if err := pt.mountBpfPinPath(); err != nil {
		return fmt.Errorf("can't mount BPF filesystem: %w", err)
	}
	return nil
}

func (pt *ProcessTracer) close() {
	pt.unmountBpfPinPath()
}

func (pt *ProcessTracer) mountBpfPinPath() error {
	pt.log.Debug("mounting BPF map pinning", "path", pt.PinPath)
	if _, err := os.Stat(pt.PinPath); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("accessing %s stat: %w", pt.PinPath, err)
		}
		pt.log.Debug("BPF map pinning path does not exist. Creating before mounting")
		if err := os.MkdirAll(pt.PinPath, 0700); err != nil {
			return fmt.Errorf("creating directory %s: %w", pt.PinPath, err)
		}
	}

	return bpfMount(pt.PinPath)
}

func (pt *ProcessTracer) unmountBpfPinPath() {
	if err := unix.Unmount(pt.PinPath, unix.MNT_FORCE); err != nil {
		pt.log.Warn("can't unmount pinned root. Try unmounting and removing it manually", err)
		return
	}
	pt.log.Debug("unmounted bpf file system")
	if err := os.RemoveAll(pt.PinPath); err != nil {
		pt.log.Warn("can't remove pinned root. Try removing it manually", err)
	} else {
		pt.log.Debug("removed pin path")
	}
}

// tracers returns Tracer implementer for each discovered eBPF traceable source: GRPC, HTTP...
func (pt *ProcessTracer) tracers() ([]Tracer, error) {
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

func bpfMount(pinPath string) error {
	return unix.Mount(pinPath, pinPath, "bpf", 0, "")
}

func RunIndependentTracer(p Tracer) error {
	i := instrumenter{}
	plog := ptlog()
	plog.Debug("loading independent eBPF program")
	spec, err := p.Load()
	if err != nil {
		return fmt.Errorf("loading eBPF program: %w", err)
	}

	if err := spec.LoadAndAssign(p.BpfObjects(), &ebpf.CollectionOptions{}); err != nil {
		printVerifierErrorInfo(err)
		return fmt.Errorf("loading and assigning BPF objects: %w", err)
	}

	if err := i.kprobes(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	go p.Run(context.Background(), nil, svc.ID{})

	return nil
}

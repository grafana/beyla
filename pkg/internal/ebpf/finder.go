//go:build linux

package ebpf

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/grafana/beyla/pkg/internal/ebpf/goruntime"
	"github.com/grafana/beyla/pkg/internal/ebpf/grpc"
	"github.com/grafana/beyla/pkg/internal/ebpf/httpfltr"
	"github.com/grafana/beyla/pkg/internal/ebpf/nethttp"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/pipe"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
)

func pflog() *slog.Logger {
	return slog.With("component", "ebpf.ProcessFinder")
}

// ProcessFinder continuously listens in background for a process matching the
// search criteria as specified to the user.
type ProcessFinder struct {
	Cfg     *pipe.Config
	Metrics imetrics.Reporter
	CtxInfo *global.ContextInfo

	goFunctionNames []string

	discoveredTracers chan *ProcessTracer
}

func (pf *ProcessFinder) Start(ctx context.Context) (<-chan *ProcessTracer, error) {
	log := pflog()
	log.Debug("Starting Process Finder")
	pf.discoveredTracers = make(chan *ProcessTracer, pf.CtxInfo.ChannelBufferLen)

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memory lock: %w", err)
	}
	go func() {
		// TODO, for multi-process inspection
		// 1. Keep searching processes matching a given search criteria
		// 2. Instrument these that haven't been instrumented already

		log.Debug("Finding process in background...")
		tracers, err := pf.findAndInstrument(ctx)
		if err != nil {
			log.Error("finding instrumentable process", err)
			return
		}
		for _, pt := range tracers {
			pf.discoveredTracers <- pt
		}
	}()
	return pf.discoveredTracers, nil
}

func (pf *ProcessFinder) newGoProgramsGroup() []Tracer {
	// Each program is an eBPF source: net/http, grpc...
	return []Tracer{
		&nethttp.Tracer{Cfg: &pf.Cfg.EBPF, Metrics: pf.Metrics},
		&nethttp.GinTracer{Tracer: nethttp.Tracer{Cfg: &pf.Cfg.EBPF, Metrics: pf.Metrics}},
		&grpc.Tracer{Cfg: &pf.Cfg.EBPF, Metrics: pf.Metrics},
		&goruntime.Tracer{Cfg: &pf.Cfg.EBPF, Metrics: pf.Metrics},
	}
}

func (pf *ProcessFinder) newNonGoProgramsGroup() []Tracer {
	return []Tracer{&httpfltr.Tracer{Cfg: pf.Cfg, Metrics: pf.Metrics}}
}

func (pf *ProcessFinder) allGoFunctionNames() []string {
	if len(pf.goFunctionNames) > 0 {
		return pf.goFunctionNames
	}
	uniqueFunctions := map[string]struct{}{}
	var functions []string
	for _, p := range pf.newGoProgramsGroup() {
		for funcName := range p.GoProbes() {
			// avoid duplicating function names
			if _, ok := uniqueFunctions[funcName]; !ok {
				uniqueFunctions[funcName] = struct{}{}
				functions = append(functions, funcName)
			}
		}
	}
	return functions
}

func (pf *ProcessFinder) findAndInstrument(ctx context.Context) ([]*ProcessTracer, error) {
	// merging all the functions from all the programs, in order to do
	// a complete inspection of the target executable
	var allFuncs []string
	if !pf.Cfg.SkipGoSpecificTracers {
		allFuncs = pf.allGoFunctionNames()
	}
	instrumentables, err := inspect(ctx, pf.Cfg, allFuncs)
	if err != nil {
		return nil, fmt.Errorf("inspecting offsets: %w", err)
	}
	var tracers []*ProcessTracer
	for _, instr := range instrumentables {
		if pt, ok := pf.getTracer(instr); ok {
			tracers = append(tracers, pt)
			if pf.Cfg.SystemWide {
				pflog().Info("system wide instrumentation")
				return tracers, nil
			}
		}
	}
	return tracers, nil
}

func (pf *ProcessFinder) getTracer(ie instrumentableExec) (*ProcessTracer, bool) {
	programs := pf.newGoProgramsGroup()
	if ie.offsets != nil {
		programs = filterNotFoundPrograms(programs, ie.offsets)
		if len(programs) == 0 {
			pflog().Debug("no instrumentable function found. Ignoring", "pid", ie.fileInfo.Pid, "cmd", ie.fileInfo.CmdExePath)
			return nil, false
		}
	} else {
		// We are not instrumenting a Go application, we override the programs
		// list with the generic kernel/socket space filters
		programs = pf.newNonGoProgramsGroup()
	}

	// Instead of the executable file in the disk, we pass the /proc/<pid>/exec
	// to allow loading it from different container/pods in containerized environments
	exe, err := link.OpenExecutable(ie.fileInfo.ProExeLinkPath)
	if err != nil {
		pflog().Warn("can't open executable. Ignoring",
			"error", err, "pid", ie.fileInfo.Pid, "cmd", ie.fileInfo.CmdExePath)
		return nil, false
	}

	return &ProcessTracer{
		programs:   programs,
		ELFInfo:    ie.fileInfo,
		goffsets:   ie.offsets,
		exe:        exe,
		pinPath:    path.Join(pf.Cfg.EBPF.BpfBaseDir, fmt.Sprintf("%d-%d", os.Getpid(), ie.fileInfo.Pid)),
		systemWide: pf.Cfg.SystemWide,
	}, true
}

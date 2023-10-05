package ebpf

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"

	"github.com/grafana/beyla/pkg/internal/ebpf/services"
	"github.com/grafana/beyla/pkg/internal/exec"
	"github.com/grafana/beyla/pkg/internal/goexec"
	"github.com/grafana/beyla/pkg/internal/pipe"
)

func inspectLog() *slog.Logger {
	return slog.With("component", "ebpf.Inspector")
}

type Instrumentable struct {
	FileInfo *exec.FileInfo
	Offsets  *goexec.Offsets
}

type Inspector struct {
	cfg       *pipe.Config
	functions []string
	pidMap    map[int32]*exec.FileInfo
}

func NewInspector(cfg *pipe.Config, functions []string) *Inspector {
	return &Inspector{cfg: cfg, functions: functions, pidMap: map[int32]*exec.FileInfo{}}
}

func (ei *Inspector) Inspect(ctx context.Context) ([]Instrumentable, error) {
	elfs, err := exec.FindExecELFs(ctx, findingCriteria(ei.cfg))
	defer func() {
		for _, e := range elfs {
			e.ELF.Close()
		}
	}()
	if err != nil {
		return nil, fmt.Errorf("looking for executable ELFs: %w", err)
	}
	// Build first a PID map so we use only the parent processes
	// in case of multiple matches
	for i := range elfs {
		ei.pidMap[elfs[i].Pid] = &elfs[i]
	}
	var out []Instrumentable
	instrumentedPids := map[int32]struct{}{}
	for i := range elfs {
		inst := ei.asInstrumentable(&elfs[i])
		// if we find multiple processes with the same parent, avoid
		// adding multiple times the parent
		if _, ok := instrumentedPids[inst.FileInfo.Pid]; !ok {
			out = append(out, inst)
			instrumentedPids[inst.FileInfo.Pid] = struct{}{}
		}
	}
	inspectLog().Debug("found instrumentable processes", "len", len(out))
	return out, nil
}

func (ei *Inspector) asInstrumentable(execElf *exec.FileInfo) Instrumentable {
	log := inspectLog().With("pid", execElf.Pid, "comm", execElf.CmdExePath)
	log.Debug("getting instrumentable information")
	// look for suitable Go application first
	offsets, ok := inspectOffsets(ei.cfg, execElf, ei.functions)
	if ok {
		// we found go offsets, let's see if this application is not a proxy
		if !isGoProxy(offsets) {
			log.Debug("identified as a Go service or client")
			return Instrumentable{FileInfo: execElf, Offsets: offsets}
		}
		log.Debug("identified as a Go proxy")
	} else {
		log.Debug("identified as a generic, non-Go executable")
	}

	// select the parent (or grandparent) of the executable, if any
	parent, ok := ei.pidMap[execElf.Ppid]
	for ok {
		execElf = parent
		log.Debug("replacing executable by its parent", "ppid", execElf.Ppid)
		parent, ok = ei.pidMap[parent.Ppid]
	}

	log.Info("Go HTTP/gRPC support not detected. Using only generic instrumentation.")
	log.Info("instrumented", "comm", execElf.CmdExePath, "pid", execElf.Pid)

	// Return the instrumentable without offsets, at is is identified as a generic
	// (or non-instrumentable Go proxy) executable
	return Instrumentable{FileInfo: execElf}
}

func inspectOffsets(cfg *pipe.Config, execElf *exec.FileInfo, functions []string) (*goexec.Offsets, bool) {
	if !cfg.SystemWide {
		log := inspectLog()
		if cfg.SkipGoSpecificTracers {
			log.Debug("skipping inspection for Go functions", "pid", execElf.Pid, "comm", execElf.CmdExePath)
		} else {
			log.Debug("inspecting", "pid", execElf.Pid, "comm", execElf.CmdExePath)
			if offsets, err := goexec.InspectOffsets(execElf, functions); err != nil {
				log.Debug("couldn't find go specific tracers", "error", err)
			} else {
				return offsets, true
			}
		}
	}
	return nil, false
}

func findingCriteria(cfg *pipe.Config) services.DefinitionCriteria {
	if cfg.SystemWide {
		// will return all the executables in the system
		return services.DefinitionCriteria{
			services.Attributes{
				Namespace: cfg.ServiceNamespace,
				Path:      services.NewPathRegexp(regexp.MustCompile(".")),
			},
		}
	}
	finderCriteria := cfg.Services
	// Merge the old, individual single-service selector,
	// with the new, map-based multi-services selector.
	if cfg.Exec.IsSet() || cfg.Port.Len() > 0 {
		finderCriteria = slices.Clone(cfg.Services)
		finderCriteria = append(finderCriteria, services.Attributes{
			Name:      cfg.ServiceName,
			Namespace: cfg.ServiceNamespace,
			Path:      cfg.Exec,
			OpenPorts: cfg.Port,
		})
	}
	return finderCriteria
}

func isGoProxy(offsets *goexec.Offsets) bool {
	for f := range offsets.Funcs {
		// if we find anything of interest other than the Go runtime, we consider this a valid application
		if !strings.HasPrefix(f, "runtime.") {
			return false
		}
	}

	return true
}

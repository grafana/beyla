package discover

import (
	"log/slog"
	"strings"

	"github.com/mariomac/pipes/pkg/node"

	"github.com/grafana/beyla/pkg/internal/exec"
	"github.com/grafana/beyla/pkg/internal/goexec"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/pipe"
	"github.com/grafana/beyla/pkg/internal/svc"
)

type ExecTyper struct {
	Cfg     *pipe.Config
	Metrics imetrics.Reporter
}

type InstrumentableType int

const (
	InstrumentableGolang = InstrumentableType(iota)
	InstrumentableGeneric
)

func (it InstrumentableType) String() string {
	switch it {
	case InstrumentableGolang:
		return "Golang"
	case InstrumentableGeneric:
		return "Generic"
	default:
		return "unknown(bug!)"
	}
}

type Instrumentable struct {
	Type InstrumentableType

	FileInfo *exec.FileInfo
	Offsets  *goexec.Offsets
}

func ExecTyperProvider(ecfg ExecTyper) (node.MiddleFunc[[]Event[ProcessMatch], []Event[Instrumentable]], error) {
	t := typer{
		cfg:              ecfg.Cfg,
		metrics:          ecfg.Metrics,
		log:              slog.With("component", "discover.ExecTyper"),
		currentPids:      map[int32]*exec.FileInfo{},
		instrumentedPids: map[int32]struct{}{},
	}
	if !ecfg.Cfg.SkipGoSpecificTracers {
		t.loadAllGoFunctionNames()
	}
	return func(in <-chan []Event[ProcessMatch], out chan<- []Event[Instrumentable]) {
		for i := range in {
			out <- t.FilterClassify(i)
		}
	}, nil
}

type typer struct {
	cfg              *pipe.Config
	metrics          imetrics.Reporter
	log              *slog.Logger
	currentPids      map[int32]*exec.FileInfo
	instrumentedPids map[int32]struct{}
	allGoFunctions   []string
}

func (t *typer) FilterClassify(evs []Event[ProcessMatch]) []Event[Instrumentable] {
	var out []Event[Instrumentable]

	elfs := make([]*exec.FileInfo, 0, len(evs))
	// Update first the PID map so we use only the parent processes
	// in case of multiple matches
	for i := range evs {
		ev := &evs[i]
		switch evs[i].Type {
		case EventCreated:
			svcID := svc.ID{Name: ev.Obj.Criteria.Name, Namespace: ev.Obj.Criteria.Namespace}
			if elfFile, err := exec.FindExecELF(ev.Obj.Process, svcID); err != nil {
				t.log.Warn("error finding process ELF. Ignoring", "error", err)
			} else {
				t.currentPids[ev.Obj.Process.Pid] = elfFile
				elfs = append(elfs, elfFile)
			}
		case EventDeleted:
			delete(t.currentPids, ev.Obj.Process.Pid)
			delete(t.instrumentedPids, ev.Obj.Process.Pid)
			out = append(out, Event[Instrumentable]{
				Type: EventDeleted,
				Obj:  Instrumentable{FileInfo: &exec.FileInfo{Pid: ev.Obj.Process.Pid}},
			})
		}
	}

	for i := range elfs {
		inst := t.asInstrumentable(elfs[i])
		// if we found a process and returned its parent, it might be already
		// instrumented. We skip it in that case
		if _, ok := t.instrumentedPids[inst.FileInfo.Pid]; !ok {
			t.log.Info("instrumenting process", "cmd", inst.FileInfo.CmdExePath, "pid", inst.FileInfo.Pid)
			out = append(out, Event[Instrumentable]{Type: EventCreated, Obj: inst})
			t.instrumentedPids[inst.FileInfo.Pid] = struct{}{}
		}
	}
	return out
}

func (t *typer) asInstrumentable(execElf *exec.FileInfo) Instrumentable {
	log := t.log.With("pid", execElf.Pid, "comm", execElf.CmdExePath)
	log.Debug("getting instrumentable information")
	// look for suitable Go application first
	offsets, ok := t.inspectOffsets(execElf)
	if ok {
		// we found go offsets, let's see if this application is not a proxy
		if !isGoProxy(offsets) {
			log.Debug("identified as a Go service or client")
			return Instrumentable{Type: InstrumentableGolang, FileInfo: execElf, Offsets: offsets}
		}
		log.Debug("identified as a Go proxy")
	} else {
		log.Debug("identified as a generic, non-Go executable")
	}

	// select the parent (or grandparent) of the executable, if any
	parent, ok := t.currentPids[execElf.Ppid]
	for ok && execElf.Ppid != execElf.Pid {
		log.Debug("replacing executable by its parent", "ppid", execElf.Ppid)
		execElf = parent
		parent, ok = t.currentPids[parent.Ppid]
	}

	log.Debug("instrumented", "comm", execElf.CmdExePath, "pid", execElf.Pid)
	// Return the instrumentable without offsets, at it is identified as a generic
	// (or non-instrumentable Go proxy) executable
	return Instrumentable{Type: InstrumentableGeneric, FileInfo: execElf}
}

func (t *typer) inspectOffsets(execElf *exec.FileInfo) (*goexec.Offsets, bool) {
	if !t.cfg.SystemWide {
		if t.cfg.SkipGoSpecificTracers {
			t.log.Debug("skipping inspection for Go functions", "pid", execElf.Pid, "comm", execElf.CmdExePath)
		} else {
			t.log.Debug("inspecting", "pid", execElf.Pid, "comm", execElf.CmdExePath)
			if offsets, err := goexec.InspectOffsets(execElf, t.allGoFunctions); err != nil {
				t.log.Debug("couldn't find go specific tracers", "error", err)
			} else {
				return offsets, true
			}
		}
	}
	return nil, false
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

func (t *typer) loadAllGoFunctionNames() {
	uniqueFunctions := map[string]struct{}{}
	t.allGoFunctions = nil
	for _, p := range newGoProgramsGroup(t.cfg, t.metrics) {
		for funcName := range p.GoProbes() {
			// avoid duplicating function names
			if _, ok := uniqueFunctions[funcName]; !ok {
				uniqueFunctions[funcName] = struct{}{}
				t.allGoFunctions = append(t.allGoFunctions, funcName)
			}
		}
	}
}

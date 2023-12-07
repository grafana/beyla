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

// ExecTyper classifies the discovered executables according to the
// executable type (Go, generic...), and filters these executables
// that are not instrumentable.
type ExecTyper struct {
	Cfg     *pipe.Config
	Metrics imetrics.Reporter
}

type Instrumentable struct {
	Type                 svc.InstrumentableType
	InstrumentationError error

	// in some runtimes, like python gunicorn, we need to allow
	// tracing both the parent pid and all of its children pid
	ChildPids []uint32

	FileInfo *exec.FileInfo
	Offsets  *goexec.Offsets
}

func ExecTyperProvider(ecfg ExecTyper) (node.MiddleFunc[[]Event[ProcessMatch], []Event[Instrumentable]], error) {
	t := typer{
		cfg:         ecfg.Cfg,
		metrics:     ecfg.Metrics,
		log:         slog.With("component", "discover.ExecTyper"),
		currentPids: map[int32]*exec.FileInfo{},
	}
	// TODO: do it per executable
	if !ecfg.Cfg.Discovery.SkipGoSpecificTracers {
		t.loadAllGoFunctionNames()
	}
	return func(in <-chan []Event[ProcessMatch], out chan<- []Event[Instrumentable]) {
		for i := range in {
			out <- t.FilterClassify(i)
		}
	}, nil
}

type typer struct {
	cfg            *pipe.Config
	metrics        imetrics.Reporter
	log            *slog.Logger
	currentPids    map[int32]*exec.FileInfo
	allGoFunctions []string
}

// FilterClassify returns the Instrumentable types for each received ProcessMatch,
// and filters out the processes that can't be instrumented (e.g. because of the lack
// of instrumentation points)
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
			if fInfo, ok := t.currentPids[ev.Obj.Process.Pid]; ok {
				delete(t.currentPids, ev.Obj.Process.Pid)
				out = append(out, Event[Instrumentable]{
					Type: EventDeleted,
					Obj:  Instrumentable{FileInfo: fInfo},
				})
			}
		}
	}

	for i := range elfs {
		inst := t.asInstrumentable(elfs[i])
		t.log.Debug(
			"found an instrumentable process",
			"type", inst.Type.String(),
			"exec", inst.FileInfo.CmdExePath, "pid", inst.FileInfo.Pid)
		out = append(out, Event[Instrumentable]{Type: EventCreated, Obj: inst})
	}
	return out
}

// asInstrumentable classifies the type of executable (Go, generic...) and,
// in case of belonging to a forked process, returns its parent.
func (t *typer) asInstrumentable(execElf *exec.FileInfo) Instrumentable {
	log := t.log.With("pid", execElf.Pid, "comm", execElf.CmdExePath)
	log.Debug("getting instrumentable information")
	// look for suitable Go application first
	offsets, ok, err := t.inspectOffsets(execElf)
	if ok {
		// we found go offsets, let's see if this application is not a proxy
		if !isGoProxy(offsets) {
			log.Debug("identified as a Go service or client")
			return Instrumentable{Type: svc.InstrumentableGolang, FileInfo: execElf, Offsets: offsets}
		}
		log.Debug("identified as a Go proxy")
	} else {
		log.Debug("identified as a generic, non-Go executable")
	}

	// select the parent (or grandparent) of the executable, if any
	var child []uint32
	parent, ok := t.currentPids[execElf.Ppid]
	for ok && execElf.Ppid != execElf.Pid &&
		// we will ignore parent processes that are not the same executable. For example,
		// to avoid wrongly instrumenting process launcher such as systemd or containerd-shimd
		// when they launch an instrumentable service
		execElf.CmdExePath == parent.CmdExePath {

		log.Debug("replacing executable by its parent", "ppid", execElf.Ppid)
		child = append(child, uint32(execElf.Pid))
		execElf = parent
		parent, ok = t.currentPids[parent.Ppid]
	}

	detectedType := exec.FindProcLanguage(execElf.Pid, execElf.ELF)

	log.Debug("instrumented", "comm", execElf.CmdExePath, "pid", execElf.Pid,
		"child", child, "language", detectedType.String())
	// Return the instrumentable without offsets, as it is identified as a generic
	// (or non-instrumentable Go proxy) executable
	return Instrumentable{Type: detectedType, FileInfo: execElf, ChildPids: child, InstrumentationError: err}
}

func (t *typer) inspectOffsets(execElf *exec.FileInfo) (*goexec.Offsets, bool, error) {
	if !t.cfg.Discovery.SystemWide {
		if t.cfg.Discovery.SkipGoSpecificTracers {
			t.log.Debug("skipping inspection for Go functions", "pid", execElf.Pid, "comm", execElf.CmdExePath)
		} else {
			t.log.Debug("inspecting", "pid", execElf.Pid, "comm", execElf.CmdExePath)
			if offsets, err := goexec.InspectOffsets(execElf, t.allGoFunctions); err != nil {
				t.log.Debug("couldn't find go specific tracers", "error", err)
				return nil, false, err
			} else {
				return offsets, true, nil
			}
		}
	}
	return nil, false, nil
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
	for _, p := range newGoTracersGroup(t.cfg, t.metrics) {
		for funcName := range p.GoProbes() {
			// avoid duplicating function names
			if _, ok := uniqueFunctions[funcName]; !ok {
				uniqueFunctions[funcName] = struct{}{}
				t.allGoFunctions = append(t.allGoFunctions, funcName)
			}
		}
	}
}

package discover

import (
	"debug/elf"
	"fmt"
	"log/slog"
	"strings"

	"github.com/mariomac/pipes/pkg/node"

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

	FileInfo *FileInfo
	Offsets  *goexec.Offsets
}

type FileInfo struct {
	Service svc.ID

	CmdExePath     string
	ProExeLinkPath string
	ELF            *elf.File
	Pid            int32
	Ppid           int32
}

func (fi *FileInfo) ExecutableName() string {
	parts := strings.Split(fi.CmdExePath, "/")
	return parts[len(parts)-1]
}

func ExecTyperProvider(ecfg ExecTyper) (node.MiddleFunc[[]Event[ProcessMatch], []Event[Instrumentable]], error) {
	t := typer{
		cfg:              ecfg.Cfg,
		metrics:          ecfg.Metrics,
		log:              slog.With("component", "discover.ExecTyper"),
		currentPids:      map[int32]*FileInfo{},
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
	currentPids      map[int32]*FileInfo
	instrumentedPids map[int32]struct{}
	allGoFunctions   []string
}

func (t *typer) FilterClassify(evs []Event[ProcessMatch]) []Event[Instrumentable] {
	var out []Event[Instrumentable]

	elfs := make([]*FileInfo, len(evs))
	// Update first the PID map so we use only the parent processes
	// in case of multiple matches
	for i := range evs {
		ev := &evs[i]
		switch evs[i].Type {
		case EventCreated:
			if elfFile, err := findExecELF(&ev.Obj); err != nil {
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
				Obj:  Instrumentable{FileInfo: &FileInfo{Pid: ev.Obj.Process.Pid}},
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

func findExecELF(pm *ProcessMatch) (*FileInfo, error) {
	exePath, err := pm.Process.Exe()
	if err != nil {
		// this might happen if you query from the port a service that does not have executable path.
		// Since this value is just for attributing, we set a default placeholder
		exePath = "unknown"
	}

	ppid, _ := pm.Process.Ppid()

	// In container environments or K8s, we can't just open the executable exe path, because it might
	// be in the volume of another pod/container. We need to access it through the /proc/<pid>/exe symbolic link
	file := FileInfo{
		Service: svc.ID{
			Name:      pm.Criteria.Name,
			Namespace: pm.Criteria.Namespace,
		},
		CmdExePath: exePath,
		// TODO: allow overriding /proc root folder
		ProExeLinkPath: fmt.Sprintf("/proc/%d/exe", pm.Process.Pid),
		Pid:            pm.Process.Pid,
		Ppid:           ppid,
	}
	if file.ELF, err = elf.Open(file.ProExeLinkPath); err != nil {
		return nil, fmt.Errorf("can't open ELF file in %s: %w", file.ProExeLinkPath, err)
	}
	return &file, nil
}

func (t *typer) asInstrumentable(execElf *FileInfo) Instrumentable {
	log := t.log.With("pid", execElf.Pid, "comm", execElf.CmdExePath)
	log.Debug("getting instrumentable information")
	// look for suitable Go application first
	offsets, ok := t.inspectOffsets(execElf, t.allGoFunctions)
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

func (t *typer) inspectOffsets(execElf *FileInfo, functions []string) (*goexec.Offsets, bool) {
	if !t.cfg.SystemWide {
		if t.cfg.SkipGoSpecificTracers {
			t.log.Debug("skipping inspection for Go functions", "pid", execElf.Pid, "comm", execElf.CmdExePath)
		} else {
			t.log.Debug("inspecting", "pid", execElf.Pid, "comm", execElf.CmdExePath)
			if offsets, err := goexec.InspectOffsets(execElf, functions); err != nil {
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

func (t *typer) loadAllGoFunctionNames() []string {
	uniqueFunctions := map[string]struct{}{}
	var functions []string
	for _, p := range newGoProgramsGroup(t.cfg, t.metrics) {
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

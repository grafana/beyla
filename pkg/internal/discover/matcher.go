package discover

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"slices"

	"github.com/mariomac/pipes/pkg/node"
	"github.com/shirou/gopsutil/process"

	"github.com/grafana/beyla/pkg/internal/discover/services"
	"github.com/grafana/beyla/pkg/internal/pipe"
)

// CriteriaMatcher filters the processes that match the discovery criteria.
type CriteriaMatcher struct {
	Cfg *pipe.Config
}

func CriteriaMatcherProvider(cm CriteriaMatcher) (node.MiddleFunc[[]Event[processAttrs], []Event[ProcessMatch]], error) {
	m := &matcher{
		log:            slog.With("component", "discover.CriteriaMatcher"),
		criteria:       FindingCriteria(cm.Cfg),
		processHistory: map[PID]*services.ProcessInfo{},
	}
	return m.run, nil
}

type matcher struct {
	log      *slog.Logger
	criteria services.DefinitionCriteria
	// processHistory keeps track of the processes that have been already matched and submitted for
	// instrumentation.
	// This avoids keep inspecting again and again client processes each time they open a new connection port
	processHistory map[PID]*services.ProcessInfo
}

// ProcessMatch matches a found process with the first selection criteria it fulfilled.
type ProcessMatch struct {
	Criteria *services.Attributes
	Process  *services.ProcessInfo
}

func (m *matcher) run(in <-chan []Event[processAttrs], out chan<- []Event[ProcessMatch]) {
	m.log.Debug("starting criteria matcher node")
	for i := range in {
		m.log.Debug("filtering processes", "len", len(i))
		o := m.filter(i)
		m.log.Debug("processes matching selection criteria", "len", len(o))
		out <- o
	}
}

func (m *matcher) filter(events []Event[processAttrs]) []Event[ProcessMatch] {
	var matches []Event[ProcessMatch]
	for _, ev := range events {
		if ev.Type == EventDeleted {
			if ev, ok := m.filterDeleted(ev.Obj); ok {
				matches = append(matches, ev)
			}
		} else {
			if ev, ok := m.filterCreated(ev.Obj); ok {
				matches = append(matches, ev)
			}
		}
	}
	return matches
}

func (m *matcher) filterCreated(obj processAttrs) (Event[ProcessMatch], bool) {
	if _, ok := m.processHistory[obj.pid]; ok {
		// this was already matched and submitted for inspection. Ignoring!
		return Event[ProcessMatch]{}, false
	}
	proc, err := processInfo(obj)
	if err != nil {
		m.log.Debug("can't get information for process", "pid", obj.pid, "error", err)
		return Event[ProcessMatch]{}, false
	}
	for i := range m.criteria {
		if m.matchProcess(proc, &m.criteria[i]) {
			comm := proc.ExePath
			m.log.Debug("found process", "pid", proc.Pid, "comm", comm)
			m.processHistory[obj.pid] = proc
			return Event[ProcessMatch]{
				Type: EventCreated,
				Obj:  ProcessMatch{Criteria: &m.criteria[i], Process: proc},
			}, true
		}
	}
	return Event[ProcessMatch]{}, false
}

func (m *matcher) filterDeleted(obj processAttrs) (Event[ProcessMatch], bool) {
	proc, ok := m.processHistory[obj.pid]
	if !ok {
		m.log.Debug("deleted untracked process. Ignoring", "pid", obj.pid)
		return Event[ProcessMatch]{}, false
	}
	delete(m.processHistory, obj.pid)
	m.log.Debug("stopped process", "pid", proc.Pid, "comm", proc.ExePath)
	return Event[ProcessMatch]{
		Type: EventDeleted,
		Obj:  ProcessMatch{Process: proc},
	}, true
}

func (m *matcher) matchProcess(p *services.ProcessInfo, a *services.Attributes) bool {
	if !a.Path.IsSet() && a.OpenPorts.Len() == 0 {
		return false
	}
	if a.Path.IsSet() && !m.matchByExecutable(p, a) {
		return false
	}
	if a.OpenPorts.Len() > 0 {
		return m.matchByPort(p, a)
	}
	return true
}

func (m *matcher) matchByPort(p *services.ProcessInfo, a *services.Attributes) bool {
	for _, c := range p.OpenPorts {
		if a.OpenPorts.Matches(int(c)) {
			return true
		}
	}
	return false
}

func (m *matcher) matchByExecutable(p *services.ProcessInfo, a *services.Attributes) bool {
	return a.Path.MatchString(p.ExePath)
}

func FindingCriteria(cfg *pipe.Config) services.DefinitionCriteria {
	if cfg.Discovery.SystemWide {
		// will return all the executables in the system
		return services.DefinitionCriteria{
			services.Attributes{
				Namespace: cfg.ServiceNamespace,
				Path:      services.NewPathRegexp(regexp.MustCompile(".")),
			},
		}
	}
	finderCriteria := cfg.Discovery.Services
	// Merge the old, individual single-service selector,
	// with the new, map-based multi-services selector.
	if cfg.Exec.IsSet() || cfg.Port.Len() > 0 {
		finderCriteria = slices.Clone(cfg.Discovery.Services)
		finderCriteria = append(finderCriteria, services.Attributes{
			Name:      cfg.ServiceName,
			Namespace: cfg.ServiceNamespace,
			Path:      cfg.Exec,
			OpenPorts: cfg.Port,
		})
	}
	return finderCriteria
}

// replaceable function to allow unit tests with faked processes
var processInfo = func(pp processAttrs) (*services.ProcessInfo, error) {
	proc, err := process.NewProcess(int32(pp.pid))
	if err != nil {
		return nil, fmt.Errorf("can't read process: %w", err)
	}
	ppid, _ := proc.Ppid()
	exePath, err := proc.Exe()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// this might happen if you query from the port a service that does not have executable path.
			// Since this value is just for attributing, we set a default placeholder
			exePath = "unknown"
		} else {
			return nil, fmt.Errorf("can't read /proc/<pid>/fd information: %w", err)
		}
	}
	return &services.ProcessInfo{
		Pid:       proc.Pid,
		PPid:      ppid,
		ExePath:   exePath,
		OpenPorts: pp.openPorts,
	}, nil
}

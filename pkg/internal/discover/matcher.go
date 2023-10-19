package discover

import (
	"log/slog"
	"regexp"
	"slices"

	"github.com/mariomac/pipes/pkg/node"

	"github.com/grafana/beyla/pkg/internal/discover/services"
	"github.com/grafana/beyla/pkg/internal/pipe"
)

// CriteriaMatcher filters the processes that match the discovery criteria.
type CriteriaMatcher struct {
	Cfg *pipe.Config
}

func CriteriaMatcherProvider(cm CriteriaMatcher) (node.MiddleFunc[[]Event[*services.ProcessInfo], []Event[ProcessMatch]], error) {
	m := &matcher{
		log:            slog.With("component", "discover.CriteriaMatcher"),
		criteria:       findingCriteria(cm.Cfg),
		processHistory: map[int32]struct{}{},
	}
	return m.run, nil
}

type matcher struct {
	log      *slog.Logger
	criteria services.DefinitionCriteria
	// processHistory keeps track of the processes that have been already matched and submitted for
	// instrumentation.
	// This avoids keep inspecting again and again client processes each time they open a new connection port
	// TODO: move to a deduper node when we handle the process elimination
	processHistory map[int32]struct{}
}

// ProcessMatch matches a found process with the first selection criteria it fulfilled.
type ProcessMatch struct {
	Criteria *services.Attributes
	Process  *services.ProcessInfo
}

func (m *matcher) run(in <-chan []Event[*services.ProcessInfo], out chan<- []Event[ProcessMatch]) {
	m.log.Debug("starting criteria matcher node")
	for i := range in {
		m.log.Debug("filtering processes", "len", len(i))
		o := m.filter(i)
		m.log.Debug("processes matching selection criteria", "len", len(o))
		out <- o
	}
}

func (m *matcher) filter(events []Event[*services.ProcessInfo]) []Event[ProcessMatch] {
	var matches []Event[ProcessMatch]
	for _, ev := range events {
		if ev.Type == EventDeleted {
			delete(m.processHistory, ev.Obj.Pid)
			continue
		}
		if _, ok := m.processHistory[ev.Obj.Pid]; ok {
			// this was already matched and submitted for inspection. Ignoring!
			continue
		}
		for i := range m.criteria {
			if m.matchProcess(ev.Obj, &m.criteria[i]) {
				comm := ev.Obj.ExePath
				m.log.Debug("found process", "pid", ev.Obj.Pid, "comm", comm)
				matches = append(matches, Event[ProcessMatch]{
					Type: EventCreated,
					Obj:  ProcessMatch{Criteria: &m.criteria[i], Process: ev.Obj},
				})
				m.processHistory[ev.Obj.Pid] = struct{}{}
				break
			}
		}
	}
	return matches
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

func findingCriteria(cfg *pipe.Config) services.DefinitionCriteria {
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

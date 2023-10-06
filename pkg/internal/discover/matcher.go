package discover

import (
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"slices"

	"github.com/mariomac/pipes/pkg/node"
	"github.com/shirou/gopsutil/net"
	"github.com/shirou/gopsutil/process"

	"github.com/grafana/beyla/pkg/internal/discover/services"
	"github.com/grafana/beyla/pkg/internal/pipe"
)

// CriteriaMatcher filters these processes that matches the discovery criteria.
type CriteriaMatcher struct {
	Cfg *pipe.Config
}

func CriteriaMatcherProvider(cm CriteriaMatcher) (node.MiddleFunc[[]Event[*process.Process], []Event[ProcessMatch]], error) {
	m := &matcher{
		log:      slog.With("component", "discover.CriteriaMatcher"),
		criteria: findingCriteria(cm.Cfg),
	}
	return m.run, nil
}

type matcher struct {
	log      *slog.Logger
	criteria services.DefinitionCriteria
}

// ProcessMatch matches a found process with the first selection criteria it fulfilled.
type ProcessMatch struct {
	Criteria *services.Attributes
	Process  *process.Process
}

func (m *matcher) run(in <-chan []Event[*process.Process], out chan<- []Event[ProcessMatch]) {
	for i := range in {
		out <- m.filter(i)
	}
}

func (m *matcher) filter(events []Event[*process.Process]) []Event[ProcessMatch] {
	var matches []Event[ProcessMatch]
	for _, ev := range events {
		if ev.Type == EventDeleted {
			// TODO: handle process deletion
			continue
		}
		for i := range m.criteria {
			if m.matchProcess(ev.Obj, &m.criteria[i]) {
				comm, _ := ev.Obj.Cmdline()
				m.log.Debug("found process", "pid", ev.Obj.Pid, "comm", comm)
				matches = append(matches, Event[ProcessMatch]{
					Type: EventCreated,
					Obj:  ProcessMatch{Criteria: &m.criteria[i], Process: ev.Obj},
				})
				break
			}
		}
	}
	return matches
}

func (m *matcher) matchProcess(p *process.Process, a *services.Attributes) bool {
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

func (m *matcher) matchByPort(p *process.Process, a *services.Attributes) bool {
	conns, err := net.ConnectionsPid("all", p.Pid)
	if err != nil {
		m.log.Warn("can't get process connections. Ignoring", "process", p.Pid, "error", err)
		return false
	}
	if len(conns) == 0 {
		// there will be processes with no open file descriptors, but unfortunately the library we use to
		// get the connections for a given 'pid' swallows any permission errors. We ensure we didn't fail to
		// find the open file descriptors because of access permissions. If we did, we log a warning to let
		// the user know they may have configuration issues.
		if err := tryAccessPid(p.Pid); err != nil {
			m.log.Warn("can't get process information, possibly because of insufficient permissions", "process", p.Pid, "error", err)
			return false
		}
	}
	for _, c := range conns {
		if a.OpenPorts.Matches(int(c.Laddr.Port)) {
			return true
		}
	}
	return false
}

func (m *matcher) matchByExecutable(p *process.Process, a *services.Attributes) bool {
	exePath, err := p.Exe()
	if err != nil {
		// expected for some processes, but it could also be due to insufficient permissions.
		// we check for insufficient permissions, log a warning, and continue
		if err := tryAccessPid(p.Pid); err != nil {
			m.log.Warn("can't get process information, possibly because of insufficient permissions", "process", p.Pid, "error", err)
		}
		return false
	}
	if !a.Path.MatchString(exePath) {
		return false
	}
	return true
}

func tryAccessPid(pid int32) error {
	// TODO: allow overriding proc root
	dir := fmt.Sprintf("/proc/%d/fd", pid)
	_, err := os.Open(dir)
	return err
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

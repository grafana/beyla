package discover

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"slices"

	"github.com/shirou/gopsutil/v3/process"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/pipe/msg"
	"github.com/grafana/beyla/v2/pkg/pipe/swarm"
	"github.com/grafana/beyla/v2/pkg/services"
)

// CriteriaMatcherProvider filters the processes that match the discovery criteria.
func CriteriaMatcherProvider(
	cfg *beyla.Config,
	input *msg.Queue[[]Event[processAttrs]],
	output *msg.Queue[[]Event[ProcessMatch]],
) swarm.InstanceFunc {
	m := &matcher{
		log:             slog.With("component", "discover.CriteriaMatcher"),
		criteria:        FindingCriteria(cfg),
		excludeCriteria: append(cfg.Discovery.ExcludeServices, cfg.Discovery.DefaultExcludeServices...),
		processHistory:  map[PID]*services.ProcessInfo{},
		input:           input.Subscribe(),
		output:          output,
	}
	return swarm.DirectInstance(m.run)
}

type matcher struct {
	log             *slog.Logger
	criteria        services.DefinitionCriteria
	excludeCriteria services.DefinitionCriteria
	// processHistory keeps track of the processes that have been already matched and submitted for
	// instrumentation.
	// This avoids keep inspecting again and again client processes each time they open a new connection port
	processHistory map[PID]*services.ProcessInfo
	input          <-chan []Event[processAttrs]
	output         *msg.Queue[[]Event[ProcessMatch]]
}

// ProcessMatch matches a found process with the first selection criteria it fulfilled.
type ProcessMatch struct {
	Criteria *services.Attributes
	Process  *services.ProcessInfo
}

func (m *matcher) run(_ context.Context) {
	defer m.output.Close()
	m.log.Debug("starting criteria matcher node")
	for i := range m.input {
		m.log.Debug("filtering processes", "len", len(i))
		o := m.filter(i)
		m.log.Debug("processes matching selection criteria", "len", len(o))
		if len(o) > 0 {
			m.output.Send(o)
		}
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
		if m.matchProcess(&obj, proc, &m.criteria[i]) && !m.isExcluded(&obj, proc) {
			m.log.Debug("found process", "pid", proc.Pid, "comm", proc.ExePath, "metadata", obj.metadata, "podLabels", obj.podLabels)
			m.processHistory[obj.pid] = proc
			return Event[ProcessMatch]{
				Type: EventCreated,
				Obj:  ProcessMatch{Criteria: &m.criteria[i], Process: proc},
			}, true
		}
	}

	// We didn't match the process, but let's see if the parent PID is tracked, it might be the child hasn't opened the port yet
	if _, ok := m.processHistory[PID(proc.PPid)]; ok {
		m.log.Debug("found process by matching the process parent id", "pid", proc.Pid, "ppid", proc.PPid, "comm", proc.ExePath, "metadata", obj.metadata)
		m.processHistory[obj.pid] = proc
		return Event[ProcessMatch]{
			Type: EventCreated,
			Obj:  ProcessMatch{Criteria: &m.criteria[0], Process: proc},
		}, true
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

func (m *matcher) isExcluded(obj *processAttrs, proc *services.ProcessInfo) bool {
	for i := range m.excludeCriteria {
		m.log.Debug("checking exclusion criteria", "pid", proc.Pid, "comm", proc.ExePath)
		if m.matchProcess(obj, proc, &m.excludeCriteria[i]) {
			return true
		}
	}
	return false
}

func (m *matcher) matchProcess(obj *processAttrs, p *services.ProcessInfo, a *services.Attributes) bool {
	log := m.log.With("pid", p.Pid, "exe", p.ExePath)
	if !a.Path.IsSet() && a.OpenPorts.Len() == 0 && len(obj.metadata) == 0 {
		log.Debug("no Kube metadata, no local selection criteria. Ignoring")
		return false
	}
	if (a.Path.IsSet() || a.PathRegexp.IsSet()) && !m.matchByExecutable(p, a) {
		log.Debug("executable path does not match", "path", a.Path, "pathregexp", a.PathRegexp)
		return false
	}
	if a.OpenPorts.Len() > 0 && !m.matchByPort(p, a) {
		log.Debug("open ports do not match", "openPorts", a.OpenPorts)
		return false
	}
	// after matching by process basic information, we check if it matches
	// by metadata.
	// If there is no metadata, this will return true.
	return m.matchByAttributes(obj, a)
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
	if a.Path.IsSet() {
		return a.Path.MatchString(p.ExePath)
	}
	return a.PathRegexp.MatchString(p.ExePath)
}

func (m *matcher) matchByAttributes(actual *processAttrs, required *services.Attributes) bool {
	if required == nil {
		return true
	}
	if actual == nil {
		return false
	}
	log := m.log.With("pid", actual.pid)
	// match metadata
	for attrName, criteriaRegexp := range required.Metadata {
		if attrValue, ok := actual.metadata[attrName]; !ok || !criteriaRegexp.MatchString(attrValue) {
			log.Debug("metadata does not match", "attr", attrName, "value", attrValue)
			return false
		}
	}

	// match pod labels
	for labelName, criteriaRegexp := range required.PodLabels {
		if actualPodLabelValue, ok := actual.podLabels[labelName]; !ok || !criteriaRegexp.MatchString(actualPodLabelValue) {
			log.Debug("pod label does not match", "label", labelName, "value", actualPodLabelValue)
			return false
		}
	}

	// match pod annotations
	for annotationName, criteriaRegexp := range required.PodAnnotations {
		if actualPodAnnotationValue, ok := actual.podAnnotations[annotationName]; !ok || !criteriaRegexp.MatchString(actualPodAnnotationValue) {
			log.Debug("pod annotation does not match", "annotation", annotationName, "value", actualPodAnnotationValue)
			return false
		}
	}
	return true
}

func FindingCriteria(cfg *beyla.Config) services.DefinitionCriteria {
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
	// normalize criteria that only define metadata (e.g. k8s)
	// but do neither define executable name nor port: configure them to match
	// any executable in the matched k8s entities
	for i := range finderCriteria {
		fc := &finderCriteria[i]
		if !fc.Path.IsSet() && fc.OpenPorts.Len() == 0 && (len(fc.Metadata) > 0 || len(fc.PodLabels) > 0 || len(fc.PodAnnotations) > 0) {
			// match any executable path
			if err := fc.Path.UnmarshalText([]byte(".")); err != nil {
				panic("bug! " + err.Error())
			}
		}
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

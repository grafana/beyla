package discover

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"

	ebpfcommon "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/common"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/swarm"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/services"
	"github.com/shirou/gopsutil/v3/process"

	"github.com/grafana/beyla/v2/pkg/beyla"
)

var namespaceFetcherFunc = ebpfcommon.FindNetworkNamespace
var hasHostPidAccess = ebpfcommon.HasHostPidAccess
var osPidFunc = os.Getpid

// CriteriaMatcherProvider filters the processes that match the discovery criteria.
func CriteriaMatcherProvider(
	cfg *beyla.Config,
	input *msg.Queue[[]Event[processAttrs]],
	output *msg.Queue[[]Event[ProcessMatch]],
) swarm.InstanceFunc {
	beylaNamespace, _ := namespaceFetcherFunc(int32(osPidFunc()))
	m := &matcher{
		log:              slog.With("component", "discover.CriteriaMatcher"),
		criteria:         FindingCriteria(cfg),
		excludeCriteria:  ExcludingCriteria(cfg),
		processHistory:   map[PID]*services.ProcessInfo{},
		input:            input.Subscribe(),
		output:           output,
		beylaNamespace:   beylaNamespace,
		hasHostPidAccess: hasHostPidAccess(),
	}
	return swarm.DirectInstance(m.run)
}

func SurveyCriteriaMatcherProvider(
	cfg *beyla.Config,
	input *msg.Queue[[]Event[processAttrs]],
	output *msg.Queue[[]Event[ProcessMatch]],
) swarm.InstanceFunc {
	beylaNamespace, _ := namespaceFetcherFunc(int32(osPidFunc()))
	m := &matcher{
		log:              slog.With("component", "discover.SurveyCriteriaMatcher"),
		criteria:         surveyCriteria(cfg),
		excludeCriteria:  surveyExcludingCriteria(cfg),
		processHistory:   map[PID]*services.ProcessInfo{},
		input:            input.Subscribe(),
		output:           output,
		beylaNamespace:   beylaNamespace,
		hasHostPidAccess: hasHostPidAccess(),
	}
	return swarm.DirectInstance(m.run)
}

type matcher struct {
	log             *slog.Logger
	criteria        []services.Selector
	excludeCriteria []services.Selector
	// processHistory keeps track of the processes that have been already matched and submitted for
	// instrumentation.
	// This avoids keep inspecting again and again client processes each time they open a new connection port
	processHistory   map[PID]*services.ProcessInfo
	input            <-chan []Event[processAttrs]
	output           *msg.Queue[[]Event[ProcessMatch]]
	beylaNamespace   string
	hasHostPidAccess bool
}

// ProcessMatch matches a found process with the first selection criteria it fulfilled.
type ProcessMatch struct {
	Criteria services.Selector
	Process  *services.ProcessInfo
}

func (m *matcher) run(ctx context.Context) {
	defer m.output.Close()
	m.log.Debug("starting criteria matcher node")
	for {
		select {
		case <-ctx.Done():
			m.log.Debug("context cancelled, stopping criteria matcher node")
			return
		case i, ok := <-m.input:
			if !ok {
				m.log.Debug("input channel closed, stopping criteria matcher node")
				return
			}
			m.log.Debug("filtering processes", "len", len(i))
			o := m.filter(i)
			m.log.Debug("processes matching selection criteria", "len", len(o))
			if len(o) > 0 {
				m.output.Send(o)
			}
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
		if m.matchProcess(&obj, proc, m.criteria[i]) && !m.isExcluded(&obj, proc) {
			m.log.Debug("found process", "pid", proc.Pid, "comm", proc.ExePath, "metadata", obj.metadata, "podLabels", obj.podLabels, "criteria", m.criteria[i])
			m.processHistory[obj.pid] = proc
			return Event[ProcessMatch]{
				Type: EventCreated,
				Obj:  ProcessMatch{Criteria: m.criteria[i], Process: proc},
			}, true
		}
	}

	// We didn't match the process, but let's see if the parent PID is tracked, it might be the child hasn't opened the port yet
	if _, ok := m.processHistory[PID(proc.PPid)]; ok {
		m.log.Debug("found process by matching the process parent id", "pid", proc.Pid, "ppid", proc.PPid, "comm", proc.ExePath, "metadata", obj.metadata)
		m.processHistory[obj.pid] = proc
		return Event[ProcessMatch]{
			Type: EventCreated,
			Obj:  ProcessMatch{Criteria: m.criteria[0], Process: proc},
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
		if m.matchProcess(obj, proc, m.excludeCriteria[i]) {
			return true
		}
	}
	return false
}

func (m *matcher) matchProcess(obj *processAttrs, p *services.ProcessInfo, a services.Selector) bool {
	log := m.log.With("pid", p.Pid, "exe", p.ExePath)
	if !a.GetPath().IsSet() && a.GetOpenPorts().Len() == 0 && len(obj.metadata) == 0 {
		log.Debug("no Kube metadata, no local selection criteria. Ignoring")
		return false
	}
	if (a.GetPath().IsSet() || a.GetPathRegexp().IsSet()) && !m.matchByExecutable(p, a) {
		log.Debug("executable path does not match", "path", a.GetPath(), "pathregexp", a.GetPathRegexp())
		return false
	}
	if a.GetOpenPorts().Len() > 0 && !m.matchByPort(p, a) {
		log.Debug("open ports do not match", "openPorts", a.GetOpenPorts(), "process ports", p.OpenPorts)
		return false
	}
	if a.IsContainersOnly() {
		ns, _ := namespaceFetcherFunc(p.Pid)
		if ns == m.beylaNamespace && m.hasHostPidAccess {
			log.Debug("not in a container", "namespace", ns)
			return false
		}
		log.Debug("app is in a container", "namespace", ns, "beyla namespace", m.beylaNamespace)
	}
	// after matching by process basic information, we check if it matches
	// by metadata.
	// If there is no metadata, this will return true.
	return m.matchByAttributes(obj, a)
}

func (m *matcher) matchByPort(p *services.ProcessInfo, a services.Selector) bool {
	for _, c := range p.OpenPorts {
		if a.GetOpenPorts().Matches(int(c)) {
			return true
		}
	}
	return false
}

func (m *matcher) matchByExecutable(p *services.ProcessInfo, a services.Selector) bool {
	if a.GetPath().IsSet() {
		return a.GetPath().MatchString(p.ExePath)
	}
	return a.GetPathRegexp().MatchString(p.ExePath)
}

func (m *matcher) matchByAttributes(actual *processAttrs, required services.Selector) bool {
	if required == nil {
		return true
	}
	if actual == nil {
		return false
	}
	log := m.log.With("pid", actual.pid)
	// match metadata
	for attrName, criteriaRegexp := range required.RangeMetadata() {
		if attrValue, ok := actual.metadata[attrName]; !ok || !criteriaRegexp.MatchString(attrValue) {
			log.Debug("metadata does not match", "attr", attrName, "value", attrValue)
			return false
		}
	}

	// match pod labels
	for labelName, criteriaRegexp := range required.RangePodLabels() {
		if actualPodLabelValue, ok := actual.podLabels[labelName]; !ok || !criteriaRegexp.MatchString(actualPodLabelValue) {
			log.Debug("pod label does not match", "label", labelName, "value", actualPodLabelValue)
			return false
		}
	}

	// match pod annotations
	for annotationName, criteriaRegexp := range required.RangePodAnnotations() {
		if actualPodAnnotationValue, ok := actual.podAnnotations[annotationName]; !ok || !criteriaRegexp.MatchString(actualPodAnnotationValue) {
			log.Debug("pod annotation does not match", "annotation", annotationName, "value", actualPodAnnotationValue)
			return false
		}
	}
	return true
}

func normalizeGlobCriteria(finderCriteria services.GlobDefinitionCriteria) []services.Selector {
	// normalize criteria that only define metadata (e.g. k8s)
	// but do neither define executable name nor port: configure them to match
	// any executable in the matched k8s entities
	criteria := make([]services.Selector, 0, len(finderCriteria))
	for i := range finderCriteria {
		fc := &finderCriteria[i]
		if !fc.Path.IsSet() && fc.OpenPorts.Len() == 0 && (len(fc.Metadata) > 0 || len(fc.PodLabels) > 0 || len(fc.PodAnnotations) > 0) {
			// match any executable path
			if err := fc.Path.UnmarshalText([]byte("*")); err != nil {
				panic("bug! " + err.Error())
			}
		}
		criteria = append(criteria, fc)
	}
	return criteria
}

func normalizeRegexCriteria(finderCriteria services.RegexDefinitionCriteria) []services.Selector {
	// normalize criteria that only define metadata (e.g. k8s)
	// but do neither define executable name nor port: configure them to match
	// any executable in the matched k8s entities
	criteria := make([]services.Selector, 0, len(finderCriteria))
	for i := range finderCriteria {
		fc := &finderCriteria[i]
		if !fc.Path.IsSet() && fc.OpenPorts.Len() == 0 && (len(fc.Metadata) > 0 || len(fc.PodLabels) > 0 || len(fc.PodAnnotations) > 0) {
			// match any executable path
			if err := fc.Path.UnmarshalText([]byte(".")); err != nil {
				panic("bug! " + err.Error())
			}
		}
		criteria = append(criteria, fc)
	}
	return criteria
}

func FindingCriteria(cfg *beyla.Config) []services.Selector {
	logDeprecationAndConflicts(cfg)

	if onlyDefinesDeprecatedServiceSelection(cfg) {
		// deprecated use case. Supporting the old discovery > services section when the
		// newest discovery > instrument is not set
		finderCriteria := cfg.Discovery.Services
		// Merge the old, individual single-service selector,
		// with the new, map-based multi-services selector.
		if cfg.Exec.IsSet() || cfg.Port.Len() > 0 {
			finderCriteria = slices.Clone(cfg.Discovery.Services)
			finderCriteria = append(finderCriteria, services.RegexSelector{
				Name:      cfg.ServiceName,
				Namespace: cfg.ServiceNamespace,
				Path:      cfg.Exec,
				OpenPorts: cfg.Port,
			})
		}
		return normalizeRegexCriteria(finderCriteria)
	}

	if len(cfg.Discovery.Instrument) > 0 {
		finderCriteria := cfg.Discovery.Instrument
		if cfg.AutoTargetExe.IsSet() || cfg.Port.Len() > 0 {
			finderCriteria = slices.Clone(cfg.Discovery.Instrument)
			finderCriteria = append(finderCriteria, services.GlobAttributes{
				Name:      cfg.ServiceName,
				Namespace: cfg.ServiceNamespace,
				Path:      cfg.AutoTargetExe,
				OpenPorts: cfg.Port,
			})
		}
		return normalizeGlobCriteria(finderCriteria)
	}

	// edge use case: when neither discovery > services nor discovery > instrument sections are set
	// we will prioritize the newer BEYLA_AUTO_TARGET_EXE/OTEL_GO_AUTO_TARGET_EXE property
	// over the old, deprecated BEYLA_EXECUTABLE_PATH
	if cfg.AutoTargetExe.IsSet() {
		return []services.Selector{
			&services.GlobAttributes{
				Name:      cfg.ServiceName,
				Namespace: cfg.ServiceNamespace,
				Path:      cfg.AutoTargetExe,
				OpenPorts: cfg.Port,
			},
		}
	}

	return []services.Selector{
		&services.RegexSelector{
			Name:      cfg.ServiceName,
			Namespace: cfg.ServiceNamespace,
			Path:      cfg.Exec,
			OpenPorts: cfg.Port,
		},
	}
}

func surveyCriteria(cfg *beyla.Config) []services.Selector {
	finderCriteria := cfg.Discovery.Survey
	return normalizeGlobCriteria(finderCriteria)
}

func ExcludingCriteria(cfg *beyla.Config) []services.Selector {
	// deprecated options: supporting them only if the user neither defines
	// the instrument nor exclude_instrument sections
	if onlyDefinesDeprecatedServiceSelection(cfg) {
		return append(regexAsSelector(cfg.Discovery.ExcludeServices),
			regexAsSelector(cfg.Discovery.DefaultExcludeServices)...)
	}
	return append(globsAsSelector(cfg.Discovery.ExcludeInstrument),
		globsAsSelector(cfg.Discovery.DefaultExcludeInstrument)...)
}

func surveyExcludingCriteria(cfg *beyla.Config) []services.Selector {
	// deprecated options: supporting them only if the user neither defines
	// the instrument nor exclude_instrument sections
	if onlyDefinesDeprecatedServiceSelection(cfg) {
		return regexAsSelector(cfg.Discovery.DefaultExcludeServices)
	}
	return globsAsSelector(cfg.Discovery.DefaultExcludeInstrument)
}

func onlyDefinesDeprecatedServiceSelection(cfg *beyla.Config) bool {
	c := &cfg.Discovery
	return (len(c.Services) > 0 || len(c.ExcludeServices) > 0) &&
		len(c.Instrument) == 0 && len(c.ExcludeInstrument) == 0
}

func globsAsSelector(in services.GlobDefinitionCriteria) []services.Selector {
	out := make([]services.Selector, 0, len(in))
	for i := range in {
		out = append(out, &in[i])
	}
	return out
}

func regexAsSelector(in services.RegexDefinitionCriteria) []services.Selector {
	out := make([]services.Selector, 0, len(in))
	for i := range in {
		out = append(out, &in[i])
	}
	return out
}

func logDeprecationAndConflicts(cfg *beyla.Config) {
	c := &cfg.Discovery
	if len(c.Services) > 0 {
		switch {
		case len(c.Instrument) > 0:
			slog.Warn("both discovery > instrument and legacy discovery > services YAML sections are defined. Using" +
				" discovery > instrument and ignoring discovery > services (also ignoring discovery > exclude_services)")
		case cfg.Exec.IsSet():
			slog.Warn("both discovery > instrument and legacy OTEL_EBPF_EXECUTABLE_NAME are defined. Using" +
				" discovery > instrument and ignoring OTEL_EBPF_EXECUTABLE_NAME")
		default:
			slog.Warn("discovery > services YAML property is deprecated and will be removed in a future version. Use" +
				" discovery > instrument instead. See documentation for more details")
		}
	}
	if len(c.ExcludeServices) > 0 {
		if len(c.ExcludeInstrument) > 0 {
			slog.Warn("discovery > exclude_services will be ignored. Use discovery > exclude_instrument instead")
		} else {
			slog.Warn("discovery > exclude_services YAML property is deprecated and will be removed in a future version. Use" +
				" discovery > exclude_instrument instead. See documentation for more details")
		}
	}
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

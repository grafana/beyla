package discover

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"

	"github.com/shirou/gopsutil/v3/process"

	ebpfcommon "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/common"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/obi"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/swarm"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/services"
)

var (
	namespaceFetcherFunc = ebpfcommon.FindNetworkNamespace
	hasHostPidAccess     = ebpfcommon.HasHostPidAccess
	osPidFunc            = os.Getpid
)

// CriteriaMatcherProvider filters the processes that match the discovery criteria.
func CriteriaMatcherProvider(
	cfg *obi.Config,
	input *msg.Queue[[]Event[ProcessAttrs]],
	output *msg.Queue[[]Event[ProcessMatch]],
) swarm.InstanceFunc {
	beylaNamespace, _ := namespaceFetcherFunc(int32(osPidFunc()))
	m := &Matcher{
		Log:              slog.With("component", "discover.CriteriaMatcher"),
		Criteria:         FindingCriteria(cfg),
		ExcludeCriteria:  ExcludingCriteria(cfg),
		ProcessHistory:   map[PID]*services.ProcessInfo{},
		Input:            input.Subscribe(),
		Output:           output,
		Namespace:        beylaNamespace,
		HasHostPidAccess: hasHostPidAccess(),
	}
	return swarm.DirectInstance(m.Run)
}

// Matcher is the component that matches the processes against the discovery criteria.
// It filters the processes that match the discovery criteria and sends them to the output channel.
type Matcher struct {
	Log             *slog.Logger
	Criteria        []services.Selector
	ExcludeCriteria []services.Selector
	// ProcessHistory keeps track of the processes that have been already matched and submitted for
	// instrumentation.
	// This avoids keep inspecting again and again client processes each time they open a new connection port
	ProcessHistory   map[PID]*services.ProcessInfo
	Input            <-chan []Event[ProcessAttrs]
	Output           *msg.Queue[[]Event[ProcessMatch]]
	Namespace        string
	HasHostPidAccess bool
}

// ProcessMatch matches a found process with the first selection criteria it fulfilled.
type ProcessMatch struct {
	Criteria services.Selector
	Process  *services.ProcessInfo
}

func (m *Matcher) Run(ctx context.Context) {
	defer m.Output.Close()
	m.Log.Debug("starting criteria matcher node")
	for {
		select {
		case <-ctx.Done():
			m.Log.Debug("context cancelled, stopping criteria matcher node")
			return
		case i, ok := <-m.Input:
			if !ok {
				m.Log.Debug("input channel closed, stopping criteria matcher node")
				return
			}
			m.Log.Debug("filtering processes", "len", len(i))
			o := m.filter(i)
			m.Log.Debug("processes matching selection criteria", "len", len(o))
			if len(o) > 0 {
				m.Output.Send(o)
			}
		}
	}
}

func (m *Matcher) filter(events []Event[ProcessAttrs]) []Event[ProcessMatch] {
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

func (m *Matcher) filterCreated(obj ProcessAttrs) (Event[ProcessMatch], bool) {
	if _, ok := m.ProcessHistory[obj.pid]; ok {
		// this was already matched and submitted for inspection. Ignoring!
		return Event[ProcessMatch]{}, false
	}
	proc, err := processInfo(obj)
	if err != nil {
		m.Log.Debug("can't get information for process", "pid", obj.pid, "error", err)
		return Event[ProcessMatch]{}, false
	}
	for i := range m.Criteria {
		if m.matchProcess(&obj, proc, m.Criteria[i]) && !m.isExcluded(&obj, proc) {
			m.Log.Debug("found process", "pid", proc.Pid, "comm", proc.ExePath, "metadata", obj.metadata, "podLabels", obj.podLabels, "criteria", m.Criteria[i])
			m.ProcessHistory[obj.pid] = proc
			return Event[ProcessMatch]{
				Type: EventCreated,
				Obj:  ProcessMatch{Criteria: m.Criteria[i], Process: proc},
			}, true
		}
	}

	// We didn't match the process, but let's see if the parent PID is tracked, it might be the child hasn't opened the port yet
	if _, ok := m.ProcessHistory[PID(proc.PPid)]; ok {
		m.Log.Debug("found process by matching the process parent id", "pid", proc.Pid, "ppid", proc.PPid, "comm", proc.ExePath, "metadata", obj.metadata)
		m.ProcessHistory[obj.pid] = proc
		return Event[ProcessMatch]{
			Type: EventCreated,
			Obj:  ProcessMatch{Criteria: m.Criteria[0], Process: proc},
		}, true
	}

	return Event[ProcessMatch]{}, false
}

func (m *Matcher) filterDeleted(obj ProcessAttrs) (Event[ProcessMatch], bool) {
	proc, ok := m.ProcessHistory[obj.pid]
	if !ok {
		m.Log.Debug("deleted untracked process. Ignoring", "pid", obj.pid)
		return Event[ProcessMatch]{}, false
	}
	delete(m.ProcessHistory, obj.pid)
	m.Log.Debug("stopped process", "pid", proc.Pid, "comm", proc.ExePath)
	return Event[ProcessMatch]{
		Type: EventDeleted,
		Obj:  ProcessMatch{Process: proc},
	}, true
}

func (m *Matcher) isExcluded(obj *ProcessAttrs, proc *services.ProcessInfo) bool {
	for i := range m.ExcludeCriteria {
		m.Log.Debug("checking exclusion criteria", "pid", proc.Pid, "comm", proc.ExePath)
		if m.matchProcess(obj, proc, m.ExcludeCriteria[i]) {
			return true
		}
	}
	return false
}

func (m *Matcher) matchProcess(obj *ProcessAttrs, p *services.ProcessInfo, a services.Selector) bool {
	log := m.Log.With("pid", p.Pid, "exe", p.ExePath)
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
		if ns == m.Namespace && m.HasHostPidAccess {
			log.Debug("not in a container", "namespace", ns)
			return false
		}
		log.Debug("app is in a container", "namespace", ns, "beyla namespace", m.Namespace)
	}
	// after matching by process basic information, we check if it matches
	// by metadata.
	// If there is no metadata, this will return true.
	return m.matchByAttributes(obj, a)
}

func (m *Matcher) matchByPort(p *services.ProcessInfo, a services.Selector) bool {
	for _, c := range p.OpenPorts {
		if a.GetOpenPorts().Matches(int(c)) {
			return true
		}
	}
	return false
}

func (m *Matcher) matchByExecutable(p *services.ProcessInfo, a services.Selector) bool {
	if a.GetPath().IsSet() {
		return a.GetPath().MatchString(p.ExePath)
	}
	return a.GetPathRegexp().MatchString(p.ExePath)
}

func (m *Matcher) matchByAttributes(actual *ProcessAttrs, required services.Selector) bool {
	if required == nil {
		return true
	}
	if actual == nil {
		return false
	}
	log := m.Log.With("pid", actual.pid)
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

func NormalizeGlobCriteria(finderCriteria services.GlobDefinitionCriteria) []services.Selector {
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

func FindingCriteria(cfg *obi.Config) []services.Selector {
	logDeprecationAndConflicts(cfg)

	if OnlyDefinesDeprecatedServiceSelection(cfg) {
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
		return NormalizeGlobCriteria(finderCriteria)
	}

	// edge use case: when neither discovery > services nor discovery > instrument sections are set
	// we will prioritize the newer OTEL_EBPF_AUTO_TARGET_EXE/OTEL_GO_AUTO_TARGET_EXE property
	// over the old, deprecated OTEL_EBPF_EXECUTABLE_PATH
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

func ExcludingCriteria(cfg *obi.Config) []services.Selector {
	// deprecated options: supporting them only if the user neither defines
	// the instrument nor exclude_instrument sections
	if OnlyDefinesDeprecatedServiceSelection(cfg) {
		return append(RegexAsSelector(cfg.Discovery.ExcludeServices),
			RegexAsSelector(cfg.Discovery.DefaultExcludeServices)...)
	}
	return append(GlobsAsSelector(cfg.Discovery.ExcludeInstrument),
		GlobsAsSelector(cfg.Discovery.DefaultExcludeInstrument)...)
}

func OnlyDefinesDeprecatedServiceSelection(cfg *obi.Config) bool {
	c := &cfg.Discovery
	return (len(c.Services) > 0 || len(c.ExcludeServices) > 0) &&
		len(c.Instrument) == 0 && len(c.ExcludeInstrument) == 0
}

func GlobsAsSelector(in services.GlobDefinitionCriteria) []services.Selector {
	out := make([]services.Selector, 0, len(in))
	for i := range in {
		out = append(out, &in[i])
	}
	return out
}

func RegexAsSelector(in services.RegexDefinitionCriteria) []services.Selector {
	out := make([]services.Selector, 0, len(in))
	for i := range in {
		out = append(out, &in[i])
	}
	return out
}

func logDeprecationAndConflicts(cfg *obi.Config) {
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
var processInfo = func(pp ProcessAttrs) (*services.ProcessInfo, error) {
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

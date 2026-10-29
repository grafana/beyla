// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"slices"
	"strings"

	"github.com/shirou/gopsutil/v4/process"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

var (
	namespaceFetcherFunc = ebpfcommon.FindNetworkNamespace
	hasHostPidAccess     = ebpfcommon.HasHostPidAccess
	osPidFunc            = os.Getpid
)

// criteriaMatcherProvider filters the processes that match the discovery criteria.
// When dynamicSelector is non-nil, only the dynamic selector is used (no config criteria),
// and the matcher listens to the selector's RemovedNotify() channel for synthetic deletes.
func criteriaMatcherProvider(
	cfg *obi.Config,
	input *msg.Queue[[]Event[ProcessAttrs]],
	output *msg.Queue[[]Event[ProcessMatch]],
	configCriteria []services.Selector,
	dynamicSelector *DynamicSelector,
	updates *services.CriteriaUpdates,
) swarm.InstanceFunc {
	instrumenterNamespace, _ := namespaceFetcherFunc(app.PID(osPidFunc()))
	if dynamicSelector != nil {
		emptyFunc, _ := swarm.EmptyRunFunc()
		return swarm.DirectInstance(emptyFunc)
	}

	m := &Matcher{
		Log:                 slog.With("component", "discover.CriteriaMatcher"),
		Criteria:            configCriteria,
		ExcludeCriteria:     ExcludingCriteria(cfg),
		LogEnricherCriteria: LogEnricherFindingCriteria(cfg),
		ProcessHistory:      map[app.PID]ProcessMatch{},
		Input:               input.Subscribe(msg.SubscriberName("discover.CriteriaMatcher")),
		Output:              output,
		Namespace:           instrumenterNamespace,
		HasHostPidAccess:    hasHostPidAccess(),
		CriteriaUpdates:     updates,
	}

	return swarm.DirectInstance(m.Run)
}

// Matcher is the component that matches the processes against the discovery criteria.
// It filters the processes that match the discovery criteria and sends them to the output channel.
type Matcher struct {
	Log                 *slog.Logger
	Criteria            []services.Selector
	ExcludeCriteria     []services.Selector
	LogEnricherCriteria []services.Selector
	// ProcessHistory keeps track of the processes that have been already matched and submitted for
	// instrumentation.
	// Without criteria updates, this avoids inspecting matched processes again when they open new ports.
	ProcessHistory   map[app.PID]ProcessMatch
	Input            <-chan []Event[ProcessAttrs]
	Output           *msg.Queue[[]Event[ProcessMatch]]
	Namespace        string
	HasHostPidAccess bool
	CriteriaUpdates  *services.CriteriaUpdates
	observed         map[app.PID]observedProcess
}

// ProcessMatch matches a found process with the first selection criteria it fulfilled.
type ProcessMatch struct {
	Criteria            []services.Selector
	LogEnricherCriteria []services.Selector
	Process             *services.ProcessInfo
	// DynamicSelectorPID is the runtime dynamic-selection owner PID. It is set by DynamicMatcher
	// on direct matches and inherited unchanged by child processes matched via PPid. CriteriaMatcher
	// leaves it zero so static discovery continues to use ProcPID downstream.
	DynamicSelectorPID app.PID
}

func (pm ProcessMatch) LogEnricherEnabled() bool {
	return len(pm.LogEnricherCriteria) > 0
}

func (m *Matcher) Run(ctx context.Context) {
	defer m.Output.Close()
	m.Log.Debug("starting criteria matcher node")

	var updates <-chan services.CriteriaUpdate
	if m.CriteriaUpdates != nil {
		updates = m.CriteriaUpdates.Requests()
		defer m.CriteriaUpdates.Stop()
		m.observed = map[app.PID]observedProcess{}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case update := <-updates:
			m.CriteriaUpdates.Complete(update, m.refresh(ctx, update))
		case events, ok := <-m.Input:
			if !ok {
				return
			}
			m.Log.Debug("filtering processes", "len", len(events))
			matches := m.filter(events)
			m.Log.Debug("processes matching selection criteria", "len", len(matches))
			if len(matches) > 0 {
				m.Output.SendCtx(ctx, matches)
			}
		}
	}
}

func (m *Matcher) filter(events []Event[ProcessAttrs]) []Event[ProcessMatch] {
	var matches []Event[ProcessMatch]
	for _, ev := range events {
		if ev.Type == EventDeleted {
			delete(m.observed, ev.Obj.pid)
			if ev, ok := m.filterDeleted(ev.Obj); ok {
				matches = append(matches, ev)
			}
		} else {
			if m.observed != nil {
				proc, err := processInfo(ev.Obj)
				if err != nil {
					m.Log.Debug("can't get information for process", "pid", ev.Obj.pid, "error", err)
					continue
				}
				observed := m.observed[ev.Obj.pid]
				observed.attrs, observed.process = ev.Obj, proc
				m.observed[ev.Obj.pid] = observed
			}
			if ev, ok := m.filterCreated(ev.Obj, m.Criteria); ok {
				matches = append(matches, ev)
			}
		}
	}
	return matches
}

func (m *Matcher) alreadyMatched(pid app.PID) bool {
	_, ok := m.ProcessHistory[pid]
	return ok
}

func (m *Matcher) confirmedMatch(pid app.PID, criterion services.Selector) bool {
	return containsCriterion(m.observed[pid].confirmedCriteria, criterion)
}

func containsCriterion(criteria []services.Selector, criterion services.Selector) bool {
	return slices.ContainsFunc(criteria, func(previous services.Selector) bool {
		return reflect.DeepEqual(previous, criterion)
	})
}

func (m *Matcher) confirmCriteria(pid app.PID, criteria []services.Selector) {
	observed, ok := m.observed[pid]
	if !ok {
		return
	}
	// Re-emissions cannot change the criteria already sent for instrumentation.
	if previous, tracked := m.ProcessHistory[pid]; tracked {
		confirmed := make([]services.Selector, 0, len(previous.Criteria))
		for _, criterion := range criteria {
			if containsCriterion(previous.Criteria, criterion) {
				confirmed = append(confirmed, criterion)
			}
		}
		criteria = confirmed
	}
	observed.confirmedCriteria = criteria
	m.observed[pid] = observed
}

func (m *Matcher) matchCriteria(obj ProcessAttrs, proc *services.ProcessInfo, findingCriteria []services.Selector) *ProcessMatch {
	criteria := make([]services.Selector, 0, len(findingCriteria))
	for _, criterion := range findingCriteria {
		if (m.confirmedMatch(obj.pid, criterion) || m.matchProcess(&obj, proc, criterion)) && !m.isExcluded(&obj, proc) {
			criteria = append(criteria, criterion)
		}
	}

	logEnricherCriteria := make([]services.Selector, 0, len(m.LogEnricherCriteria))
	for i := range m.LogEnricherCriteria {
		if m.matchProcess(&obj, proc, m.LogEnricherCriteria[i]) {
			logEnricherCriteria = append(logEnricherCriteria, m.LogEnricherCriteria[i])
		}
	}
	// Keep inherited log enrichment while an inherited include rule remains confirmed.
	if len(logEnricherCriteria) == 0 {
		for _, criterion := range criteria {
			if m.confirmedMatch(obj.pid, criterion) {
				logEnricherCriteria = m.observed[obj.pid].inheritedLogEnricherCriteria
				break
			}
		}
	}

	if len(criteria) > 0 {
		m.Log.Debug("found process", "pid", proc.Pid, "comm", proc.ExePath, "metadata",
			obj.metadata, "podLabels", obj.podLabels, "criteria", criteria, "logEnricherCriteria", logEnricherCriteria)

		return &ProcessMatch{Criteria: criteria, LogEnricherCriteria: logEnricherCriteria, Process: proc}
	}

	if len(logEnricherCriteria) > 0 {
		m.Log.Info(
			"avoiding log instrumentation for process, since it wasn't matched for instrumentation. Log enrichment criteria must be a subset of instrumentation matching criteria",
			"pid", proc.Pid,
			"comm", proc.ExePath,
			"metadata", obj.metadata,
			"podLabels", obj.podLabels,
			"criteria", criteria,
			"logEnricherCriteria", logEnricherCriteria,
		)
	}

	return nil
}

func (m *Matcher) filterCreated(obj ProcessAttrs, findingCriteria []services.Selector) (Event[ProcessMatch], bool) {
	tracked := m.alreadyMatched(obj.pid)
	if tracked && m.observed == nil {
		return Event[ProcessMatch]{}, false
	}

	proc, err := m.processInfo(obj)
	if err != nil {
		m.Log.Debug("can't get information for process", "pid", obj.pid, "error", err)
		return Event[ProcessMatch]{}, false
	}

	if processMatch := m.matchCriteria(obj, proc, findingCriteria); processMatch != nil {
		m.confirmCriteria(obj.pid, processMatch.Criteria)
		if tracked {
			return Event[ProcessMatch]{}, false
		}
		m.ProcessHistory[obj.pid] = *processMatch

		return Event[ProcessMatch]{
			Type: EventCreated,
			Obj:  *processMatch,
		}, true
	}

	// We didn't match the process, but let's see if the parent PID is tracked, it might be the child hasn't opened the port yet
	if procMatch, ok := m.ProcessHistory[proc.PPid]; ok && !m.isExcluded(&obj, proc) {
		m.confirmCriteria(obj.pid, procMatch.Criteria)
		if observed, ok := m.observed[obj.pid]; ok {
			observed.inheritedLogEnricherCriteria = procMatch.LogEnricherCriteria
			m.observed[obj.pid] = observed
		}
		if tracked {
			return Event[ProcessMatch]{}, false
		}
		m.Log.Debug("found process by matching the process parent id", "pid", proc.Pid, "ppid", proc.PPid, "comm", proc.ExePath, "metadata", obj.metadata)

		procMatch.Process = proc

		m.ProcessHistory[obj.pid] = procMatch

		return Event[ProcessMatch]{
			Type: EventCreated,
			Obj:  procMatch,
		}, true
	}

	if tracked {
		return m.filterDeleted(obj)
	}
	return Event[ProcessMatch]{}, false
}

func (m *Matcher) filterDeleted(obj ProcessAttrs) (Event[ProcessMatch], bool) {
	procMatch, ok := m.ProcessHistory[obj.pid]
	if !ok {
		m.Log.Debug("deleted untracked process. Ignoring", "pid", obj.pid)
		return Event[ProcessMatch]{}, false
	}
	delete(m.ProcessHistory, obj.pid)
	if observed, ok := m.observed[obj.pid]; ok {
		observed.confirmedCriteria = nil
		observed.inheritedLogEnricherCriteria = nil
		m.observed[obj.pid] = observed
	}
	m.Log.Debug("stopped process", "pid", procMatch.Process.Pid, "comm", procMatch.Process.ExePath)
	return Event[ProcessMatch]{
		Type: EventDeleted,
		Obj:  procMatch,
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
	pids, hasPIDs := a.GetPIDs()
	if hasPIDs && len(pids) > 0 && !pidInList(p.Pid, pids) {
		return false
	}

	if !a.GetPath().IsSet() && !a.GetLanguages().IsSet() && !a.GetCmdArgs().IsSet() && a.GetOpenPorts().Len() == 0 && len(obj.metadata) == 0 {
		if !hasPIDs || len(pids) == 0 {
			log.Debug("no Kube metadata, no local selection criteria. Ignoring")
			return false
		}
	}
	if (a.GetPath().IsSet() || a.GetPathRegexp().IsSet()) && !m.matchByExecutable(p, a) {
		log.Debug("executable path does not match", "path", a.GetPath(), "pathregexp", a.GetPathRegexp())
		return false
	}
	if a.GetCmdArgs().IsSet() && !m.matchByCommandArgs(p, a) {
		log.Debug("command line arguments do not match", "path", a.GetPath(), "commandline", a.GetCmdArgs())
		return false
	}
	if a.GetOpenPorts().Len() > 0 && !m.matchByPort(p, a) {
		log.Debug("open ports do not match", "openPorts", a.GetOpenPorts(), "process ports", p.OpenPorts)
		return false
	}
	if a.GetLanguages().IsSet() && !m.matchByLanguage(obj, a) {
		log.Debug("executable language does not match", "languages", a.GetLanguages(), "type", obj.detectedType.String())
		return false
	}
	if a.IsContainersOnly() {
		ns, _ := namespaceFetcherFunc(p.Pid)
		if ns == m.Namespace && m.HasHostPidAccess {
			log.Debug("not in a container", "namespace", ns)
			return false
		}
		log.Debug("app is in a container", "namespace", ns, "instrumenter namespace", m.Namespace)
	}
	// after matching by process basic information, we check if it matches
	// by metadata.
	// If there is no metadata, this will return true.
	return m.matchByAttributes(obj, a)
}

func pidInList(pid app.PID, list []app.PID) bool {
	return slices.Contains(list, pid)
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

func (m *Matcher) matchByLanguage(actual *ProcessAttrs, a services.Selector) bool {
	return a.GetLanguages().MatchString(actual.detectedType.String())
}

func (m *Matcher) matchByCommandArgs(p *services.ProcessInfo, a services.Selector) bool {
	if a.GetCmdArgs().IsSet() {
		return a.GetCmdArgs().MatchString(p.CmdArgs)
	}
	return false
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
		if !fc.Path.IsSet() && !fc.PathRegexp.IsSet() && fc.OpenPorts.Len() == 0 && (len(fc.Metadata) > 0 || len(fc.PodLabels) > 0 || len(fc.PodAnnotations) > 0) {
			// match any executable path
			if err := fc.Path.UnmarshalText([]byte(".")); err != nil {
				panic("bug! " + err.Error())
			}
		}
		criteria = append(criteria, fc)
	}
	return criteria
}

func LogEnricherFindingCriteria(cfg *obi.Config) []services.Selector {
	var selectors []services.Selector

	if !cfg.EBPF.LogEnricher.Enabled() {
		return selectors
	}

	for _, svcs := range cfg.EBPF.LogEnricher.Services {
		selectors = append(selectors, NormalizeGlobCriteria(svcs.Service)...)
	}

	return selectors
}

// FindingCriteria returns discovery criteria from config.
func FindingCriteria(cfg *obi.Config) []services.Selector {
	if cfg.TargetPIDs.Len() > 0 {
		vals := cfg.TargetPIDs.AllValues()
		pids := make([]uint32, 0, len(vals))
		for _, v := range vals {
			pids = append(pids, uint32(v))
		}
		return []services.Selector{
			&services.GlobAttributes{
				Name:      cfg.ServiceName,
				Namespace: cfg.ServiceNamespace,
				PIDs:      pids,
			},
		}
	}

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
		if cfg.AutoTargetExe.IsSet() || cfg.Port.Len() > 0 || cfg.AutoTargetLanguage.IsSet() {
			finderCriteria = slices.Clone(cfg.Discovery.Instrument)
			finderCriteria = append(finderCriteria, services.GlobAttributes{
				Name:      cfg.ServiceName,
				Namespace: cfg.ServiceNamespace,
				Path:      cfg.AutoTargetExe,
				OpenPorts: cfg.Port,
				Languages: cfg.AutoTargetLanguage,
			})
		}
		return NormalizeGlobCriteria(finderCriteria)
	}

	// edge use case: when neither discovery > services nor discovery > instrument sections are set
	// we will prioritize the newer OTEL_EBPF_AUTO_TARGET_EXE/OTEL_GO_AUTO_TARGET_EXE property
	// over the old, deprecated OTEL_EBPF_EXECUTABLE_PATH
	if cfg.AutoTargetExe.IsSet() || cfg.AutoTargetLanguage.IsSet() {
		return []services.Selector{
			&services.GlobAttributes{
				Name:      cfg.ServiceName,
				Namespace: cfg.ServiceNamespace,
				Path:      cfg.AutoTargetExe,
				OpenPorts: cfg.Port,
				Languages: cfg.AutoTargetLanguage,
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
	cmdLine, err := proc.Cmdline()
	// the command line includes the process name, let's get rid of it.
	if err == nil {
		_, cmdLine, _ = strings.Cut(cmdLine, " ")
	}
	return &services.ProcessInfo{
		Pid:       app.PID(proc.Pid),
		PPid:      app.PID(ppid),
		ExePath:   exePath,
		CmdArgs:   cmdLine,
		OpenPorts: pp.openPorts,
	}, nil
}

func (m *Matcher) processInfo(obj ProcessAttrs) (*services.ProcessInfo, error) {
	if observed, ok := m.observed[obj.pid]; ok {
		return observed.process, nil
	}
	return processInfo(obj)
}

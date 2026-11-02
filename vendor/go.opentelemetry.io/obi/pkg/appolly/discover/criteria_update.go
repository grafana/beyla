// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"sync"

	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/obi"
)

// CriteriaUpdater replaces discovery predicates without restarting the instrumentation pipeline.
// Exporter callbacks and endpoint providers remain those supplied at startup.
// Pass it to instrumenter.WithCriteriaUpdater. Configurations must not be mutated after submission.
// Create a new updater for each pipeline run.
type CriteriaUpdater struct {
	mu            sync.Mutex
	fixedConfig   obi.Config
	traceHeaders  map[string]string
	metricHeaders map[string]string
	features      export.Features
	updates       *services.CriteriaUpdates
}

func NewCriteriaUpdater(cfg *obi.Config) *CriteriaUpdater {
	return &CriteriaUpdater{
		fixedConfig:   withoutSelectionAndSinks(cfg),
		traceHeaders:  injectedHeaders(cfg.Traces.InjectHeaders),
		metricHeaders: injectedHeaders(cfg.OTELMetrics.InjectHeaders),
		features:      cfg.JoinMetricsConfig().Features,
		updates: services.NewCriteriaUpdates(
			refreshableCriteria(cfg),
			ExcludingCriteria(cfg),
		),
	}
}

func (u *CriteriaUpdater) Updates() *services.CriteriaUpdates { return u.updates }

// Update waits until the matcher applies the replacement, or rejects an incompatible change.
func (u *CriteriaUpdater) Update(ctx context.Context, cfg *obi.Config) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	if !reflect.DeepEqual(u.fixedConfig, withoutSelectionAndSinks(cfg)) ||
		!maps.Equal(u.traceHeaders, injectedHeaders(cfg.Traces.InjectHeaders)) ||
		!maps.Equal(u.metricHeaders, injectedHeaders(cfg.OTELMetrics.InjectHeaders)) {
		return errors.New("only discovery selection criteria can be refreshed; restart OBI to apply other configuration changes")
	}

	if cfg.JoinMetricsConfig().Features&^(u.features|export.FeatureEmpty) != 0 {
		return errors.New("new metric features require pipeline initialization; restart OBI to apply this configuration")
	}

	if err := cfg.Discovery.Validate(); err != nil {
		return err
	}

	include, exclude := refreshableCriteria(cfg), ExcludingCriteria(cfg)
	current, _ := u.updates.Current()
	if err := compatibleDefinitions(current, include); err != nil {
		return err
	}

	return u.updates.Replace(ctx, include, exclude)
}

func withoutSelectionAndSinks(cfg *obi.Config) obi.Config {
	fixed := *cfg
	fixed.Traces.TracesExport = nil
	fixed.Traces.OTLPEndpointProvider = nil
	fixed.Traces.InjectHeaders = nil
	fixed.OTELMetrics.MetricsExport = nil
	fixed.OTELMetrics.OTLPEndpointProvider = nil
	fixed.OTELMetrics.InjectHeaders = nil
	fixed.Port = services.IntEnum{}
	fixed.TargetPIDs = services.IntEnum{}
	fixed.Exec = services.RegexpAttr{}
	fixed.AutoTargetExe = services.GlobAttr{}
	fixed.AutoTargetLanguage = services.GlobAttr{}
	fixed.Discovery.Instrument = nil
	fixed.Discovery.Services = nil
	fixed.Discovery.ExcludeInstrument = nil
	fixed.Discovery.ExcludeServices = nil
	fixed.Discovery.DefaultExcludeInstrument = nil
	fixed.Discovery.DefaultExcludeServices = nil
	return fixed
}

// V2 stores declarative headers in closures, so compare their resolved values.
func injectedHeaders(inject func(map[string]string)) map[string]string {
	headers := map[string]string{}
	if inject != nil {
		inject(headers)
	}
	return headers
}

type selectorSettings struct {
	name      string
	namespace string
	exports   services.ExportModes
	sampler   *services.SamplerConfig
	routes    *services.CustomRoutesConfig
	metrics   perapp.SvcMetricsConfig
}

func settingsFor(s services.Selector) selectorSettings {
	return selectorSettings{
		name:      s.GetName(),
		namespace: s.GetNamespace(),
		exports:   s.GetExportModes(),
		sampler:   s.GetSamplerConfig(),
		routes:    s.GetRoutesConfig(),
		metrics:   s.MetricsConfig(),
	}
}

// The v2 converter makes defaults explicit on every include rule once any rule is refined,
// so the last matching rule wins as a whole. On their own, those explicit defaults behave
// like unset values and must not be reported as settings changes.
func (s selectorSettings) withoutExplicitDefaults() selectorSettings {
	if s.exports.CanExportTraces() && s.exports.CanExportMetrics() && s.exports.CanExportLogs() {
		s.exports = services.ExportModeUnset
	}

	if s.routes != nil && len(s.routes.Incoming) == 0 && len(s.routes.Outgoing) == 0 && s.routes.PolicyOverrides == nil {
		s.routes = nil
	}

	return s
}

func sameSettings(a, b selectorSettings) bool {
	return reflect.DeepEqual(a.withoutExplicitDefaults(), b.withoutExplicitDefaults())
}

func matchingSettings(criteria []services.Selector) selectorSettings {
	var settings selectorSettings
	for _, criterion := range criteria {
		next := settingsFor(criterion)
		if next.name != "" {
			settings.name = next.name
		}

		if next.namespace != "" {
			settings.namespace = next.namespace
		}

		if next.exports != services.ExportModeUnset {
			settings.exports = next.exports
		}

		if next.sampler != nil {
			settings.sampler = next.sampler
		}

		if next.routes != nil {
			settings.routes = next.routes
		}

		settings.metrics = next.metrics
	}
	return settings
}

type observedProcess struct {
	attrs   ProcessAttrs
	process *services.ProcessInfo
	// Includes confirmed by watcher events, directly or through a parent,
	// remain matched until removed or excluded.
	// A refresh using cached attributes cannot confirm a newly introduced rule.
	confirmedCriteria            []services.Selector
	inheritedLogEnricherCriteria []services.Selector
}

// refresh rematches observed processes and rejects changes to retained services before emitting events.
func (m *Matcher) refresh(ctx context.Context, update services.CriteriaUpdate) error {
	if err := update.Context.Err(); err != nil {
		return err
	}

	next := *m
	next.observed = maps.Clone(m.observed)
	next.Criteria = update.Include
	next.ExcludeCriteria = update.Exclude
	next.ProcessHistory = map[app.PID]ProcessMatch{}
	freshPorts, err := next.refreshRetainedPorts(update.Context, m)
	if err != nil {
		return err
	}
	visited := map[app.PID]bool{}

	for pid := range m.observed {
		next.rematch(pid, visited, m)
	}

	var events []Event[ProcessMatch]
	var conflictingPID app.PID
	var hasConflict bool
	for pid, previous := range m.ProcessHistory {
		replacement, retained := next.ProcessHistory[pid]
		if retained {
			matchingSettings := sameSettings(matchingSettings(previous.Criteria), matchingSettings(replacement.Criteria))
			if !matchingSettings ||
				previous.LogEnricherEnabled() != replacement.LogEnricherEnabled() {
				if !hasConflict || pid < conflictingPID {
					conflictingPID = pid
				}
				hasConflict = true
			}
			continue
		}

		events = append(events, Event[ProcessMatch]{Type: EventDeleted, Obj: previous})
	}
	if hasConflict {
		// A stable PID keeps retries of the same rejection from bypassing log deduplication.
		return fmt.Errorf("service settings would change for PID %d; restart OBI to apply this configuration", conflictingPID)
	}

	for pid, match := range next.ProcessHistory {
		if _, retained := m.ProcessHistory[pid]; !retained {
			events = append(events, Event[ProcessMatch]{Type: EventCreated, Obj: match})
		}
	}

	if err := update.Context.Err(); err != nil {
		return err
	}

	for pid, observed := range next.observed {
		if freshPorts[pid] && next.alreadyMatched(pid) {
			// These matches were confirmed with current ports, including newly added rules.
			continue
		}
		observed.confirmedCriteria = nil
		if next.alreadyMatched(pid) {
			for _, criterion := range next.Criteria {
				if m.confirmedMatch(pid, criterion) {
					observed.confirmedCriteria = append(observed.confirmedCriteria, criterion)
				}
			}
		}
		if len(observed.confirmedCriteria) == 0 {
			observed.inheritedLogEnricherCriteria = nil
		}
		next.observed[pid] = observed
	}

	m.observed = next.observed
	m.Criteria = next.Criteria
	m.ExcludeCriteria = next.ExcludeCriteria
	m.ProcessHistory = next.ProcessHistory

	if len(events) > 0 {
		m.Output.SendCtx(ctx, events)
	}

	return nil
}

func (m *Matcher) refreshRetainedPorts(ctx context.Context, previous *Matcher) (map[app.PID]bool, error) {
	fresh := map[app.PID]bool{}
	for _, pid := range slices.Sorted(maps.Keys(previous.ProcessHistory)) {
		applied := matchingSettings(previous.ProcessHistory[pid].Criteria)
		var needsPorts, settingsMayChange bool
		for _, criterion := range m.criteriaForRefresh(pid, previous) {
			needsPorts = needsPorts || (criterion.GetOpenPorts().Len() > 0 && !previous.confirmedMatch(pid, criterion))
			settingsMayChange = settingsMayChange || !sameSettings(applied, settingsFor(criterion))
		}

		for _, criterion := range m.ExcludeCriteria {
			needsPorts = needsPorts || criterion.GetOpenPorts().Len() > 0
		}

		// Only retained services whose settings could change need a synchronous port read.
		if !needsPorts || !settingsMayChange {
			continue
		}

		if err := ctx.Err(); err != nil {
			return nil, err
		}

		ports, err := processPorts(ctx, pid)
		if err != nil {
			return nil, fmt.Errorf("refreshing ports for PID %d: %w", pid, err)
		}

		observed := m.observed[pid]
		proc := *observed.process
		proc.OpenPorts = ports
		observed.attrs.openPorts = ports
		observed.process = &proc
		m.observed[pid] = observed
		fresh[pid] = true
	}

	return fresh, nil
}

func (m *Matcher) rematch(pid app.PID, visiting map[app.PID]bool, previous *Matcher) {
	if m.alreadyMatched(pid) || visiting[pid] {
		return
	}

	observed, ok := m.observed[pid]
	if !ok {
		return
	}

	visiting[pid] = true
	m.rematch(observed.process.PPid, visiting, previous)

	// Retained-service checks may refresh ports; other attributes use the last successful observation.
	m.filterCreated(observed.attrs, m.criteriaForRefresh(pid, previous))
}

func (m *Matcher) criteriaForRefresh(pid app.PID, previous *Matcher) []services.Selector {
	applied, tracked := previous.ProcessHistory[pid]
	if !tracked {
		return m.Criteria
	}

	retainsApplied := false
	criteria := make([]services.Selector, 0, len(m.Criteria))
	for _, criterion := range m.Criteria {
		if containsCriterion(applied.Criteria, criterion) {
			retainsApplied = true
			criteria = append(criteria, criterion)
		} else if !containsCriterion(previous.Criteria, criterion) {
			criteria = append(criteria, criterion)
		}
	}
	if !retainsApplied {
		return m.Criteria
	}
	// Unchanged rules that were never applied must not alter a retained service.
	// Added or edited rules still undergo the usual service-settings checks.
	return criteria
}

func refreshableCriteria(cfg *obi.Config) []services.Selector {
	if !cfg.Enabled(obi.FeatureAppO11y) {
		return nil
	}

	return FindingCriteria(cfg)
}

// Definitions may be added, removed or reordered, but existing service settings cannot be replaced.
func compatibleDefinitions(current, next []services.Selector) error {
	if !definitionsKeepSettings(current, next) {
		return errors.New("service settings changed in discovery definitions; restart OBI to apply this configuration")
	}

	byPredicate := map[string][]selectorSettings{}
	for _, previous := range current {
		key, err := predicateKey(previous)
		if err != nil {
			return err
		}
		byPredicate[key] = append(byPredicate[key], settingsFor(previous))
	}

	for _, candidate := range next {
		key, err := predicateKey(candidate)
		if err != nil {
			return err
		}

		previous, exists := byPredicate[key]
		if !exists {
			continue
		}

		found := false
		for _, settings := range previous {
			if sameSettings(settings, settingsFor(candidate)) {
				found = true
				break
			}
		}

		if !found {
			return errors.New("service settings changed for an existing discovery predicate; restart OBI to apply this configuration")
		}
	}

	return nil
}

func predicateKey(selector services.Selector) (string, error) {
	var predicates any
	switch value := selector.(type) {
	case *services.GlobAttributes:
		match := *value
		match.Name = ""
		match.Namespace = ""
		match.ExportModes = services.ExportModeUnset
		match.SamplerConfig = nil
		match.Routes = nil
		match.Metrics = perapp.SvcMetricsConfig{}
		predicates = match
	case *services.RegexSelector:
		match := *value
		match.Name = ""
		match.Namespace = ""
		match.ExportModes = services.ExportModeUnset
		match.SamplerConfig = nil
		match.Routes = nil
		match.Metrics = perapp.SvcMetricsConfig{}
		predicates = match
	default:
		return "", errors.New("unsupported discovery selector for config refresh; restart OBI")
	}

	data, err := yaml.Marshal(predicates)
	return string(data), err
}

func definitionsKeepSettings(current, next []services.Selector) bool {
	remaining := append([]services.Selector(nil), current...)
	added := 0

	for _, candidate := range next {
		matched := -1

		for i, previous := range remaining {
			if sameSettings(settingsFor(previous), settingsFor(candidate)) {
				matched = i
				break
			}
		}

		if matched < 0 {
			added++
			continue
		}

		remaining = append(remaining[:matched], remaining[matched+1:]...)
	}

	return len(remaining) == 0 || added == 0
}

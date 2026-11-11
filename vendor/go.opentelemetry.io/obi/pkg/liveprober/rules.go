// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package liveprober // import "go.opentelemetry.io/obi/pkg/liveprober"

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gobwas/glob"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
)

type SymbolResolver interface {
	ResolveLiveSymbols(app.PID, string) ([]string, error)
}

type ProcessMatcher func(services.GlobDefinitionCriteria) bool

type ProbeResult struct {
	PID              int    `json:"pid"`
	Function         string `json:"function"`
	SpanName         string `json:"span_name"`
	ServiceName      string `json:"service_name"`
	ServiceNamespace string `json:"service_namespace"`
	Status           string `json:"status"`
	Error            string `json:"error,omitempty"`
}

type dynamicKey struct {
	pid      int
	function string
}
type dynamicAttachment struct {
	cookie uint64
	result ProbeResult
	span   config.CustomSpanSpec
	link   io.Closer
}

type ruleState struct {
	matched    []int
	definition config.DynamicInstrumentationRule
	results    []ProbeResult
	// patchExpiry holds the absolute expiry of each patch, keyed by PatchSpec.Target.
	patchExpiry map[string]time.Time
}

func (m *Manager) Configure(cfg config.DynamicInstrumentationConfig, symbols SymbolResolver, metrics imetrics.Reporter) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.symbols = symbols
	m.maxProbes = cfg.MaxProbes
	m.requestTimeout = cfg.RequestTimeout
	if metrics != nil {
		m.metrics = metrics
	}
}

func (m *Manager) Changed() <-chan struct{} { return m.changed }

func (m *Manager) notifyLocked() {
	select {
	case m.changed <- struct{}{}:
	default:
	}
	close(m.updated)
	m.updated = make(chan struct{})
}

// ObserveProcess retains the discovery pipeline's matcher, including its enriched metadata.
func (m *Manager) ObserveProcess(pid int, match ProcessMatcher) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	m.matches[pid] = match
}

func (m *Manager) Selection(pid int) services.GlobDefinitionCriteria {
	m.mu.Lock()
	defer m.mu.Unlock()
	match := m.matches[pid]
	if match == nil {
		return nil
	}
	var criteria services.GlobDefinitionCriteria
	for _, id := range m.ruleIDsLocked() {
		rule := m.rules[id]
		for _, selector := range rule.definition.Service {
			if match(services.GlobDefinitionCriteria{selector}) {
				criteria = append(criteria, selector)
			}
		}
	}
	return criteria
}

func (m *Manager) SetService(pid int, service svc.Attrs) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	m.services[pid] = service.UID
	for key, attachment := range m.dynamic {
		if key.pid != pid {
			continue
		}
		updated := m.resultLocked(pid, key.function, attachment.result.SpanName)
		updated.Status = attachment.result.Status
		m.reportInvocationsLocked(attachment.cookie, pid, key.function, attachment.link)
		if updated == attachment.result {
			continue
		}
		m.reportProbe(attachment.result, 0)
		m.reportProbe(updated, 1)
		attachment.result = updated
	}
	if err := m.reconcileLocked(); err != nil {
		slog.Warn("reconciling dynamic instrumentation", "error", err)
	}
	m.notifyLocked()
}

func (m *Manager) ApplyRule(id string, rule config.DynamicInstrumentationRule) ([]ProbeResult, error) {
	if err := rule.Validate(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, errors.New("dynamic instrumentation is shutting down")
	}
	m.rules["api/"+id] = ruleState{definition: rule, patchExpiry: patchExpiries(m.rules["api/"+id], rule)}
	m.restoreRuleLocked(rule)
	err := m.reconcileLocked()
	m.notifyLocked()
	return slices.Clone(m.rules["api/"+id].results), err
}

func (m *Manager) restoreRuleLocked(rule config.DynamicInstrumentationRule) {
	for _, span := range rule.Spans {
		var pattern glob.Glob
		if span.IsAnyFunction() {
			pattern, _ = glob.Compile(span.FunctionSymbol())
		}
		for key := range m.suppressed {
			if key.function != span.TargetIdentifier() && (pattern == nil || !pattern.Match(key.function)) {
				continue
			}
			if match := m.matches[key.pid]; match != nil && match(rule.Service) {
				delete(m.suppressed, key)
			}
		}
	}
}

func (m *Manager) SetConfigRules(rules []config.DynamicInstrumentationRule) error {
	for i := range rules {
		if err := rules[i].Validate(); err != nil {
			return err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("dynamic instrumentation is shutting down")
	}
	priorConfig := map[string]ruleState{}
	for id := range m.rules {
		if len(id) >= 7 && id[:7] == "config/" {
			priorConfig[id] = m.rules[id]
			delete(m.rules, id)
		}
	}
	for i, rule := range rules {
		m.restoreRuleLocked(rule)
		key := fmt.Sprintf("config/%d", i)
		m.rules[key] = ruleState{definition: rule, patchExpiry: patchExpiries(priorConfig[key], rule)}
	}
	err := m.reconcileLocked()
	m.notifyLocked()
	return err
}

func (m *Manager) DeleteRule(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.rules, "api/"+id)
	err := m.reconcileLocked()
	m.notifyLocked()
	return err
}

func (m *Manager) RuleResults(id string) ([]ProbeResult, <-chan struct{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.rules["api/"+id].results), m.updated
}

func (m *Manager) ruleIDsLocked() []string {
	ids := make([]string, 0, len(m.rules))
	for id := range m.rules {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// RefreshMatches observes selector metadata changes without reparsing unchanged targets.
func (m *Manager) RefreshMatches() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	symbolsChanged := false
	for _, target := range m.targets {
		if resolver, ok := target.tracer.(interface{ LiveSymbolsChanged() bool }); ok {
			symbolsChanged = resolver.LiveSymbolsChanged() || symbolsChanged
		}
	}
	if symbolsChanged {
		if err := m.reconcileLocked(); err != nil {
			slog.Warn("reconciling dynamic instrumentation", "error", err)
		}
		m.notifyLocked()
		return
	}
	for _, rule := range m.rules {
		if !slices.Equal(rule.matched, m.matchingPIDsLocked(rule.definition.Service)) {
			if err := m.reconcileLocked(); err != nil {
				slog.Warn("reconciling dynamic instrumentation", "error", err)
			}
			m.notifyLocked()
			return
		}
	}
}

func (m *Manager) matchingPIDsLocked(criteria services.GlobDefinitionCriteria) []int {
	var pids []int
	for pid, match := range m.matches {
		if match(criteria) {
			pids = append(pids, pid)
		}
	}
	slices.Sort(pids)
	return pids
}

func (m *Manager) reconcileLocked() error {
	desired := map[dynamicKey]config.CustomSpanSpec{}
	desiredPatches := map[patchKey]config.PatchSpec{}
	var joined error
	for _, id := range m.ruleIDsLocked() {
		rule := m.rules[id]
		previousResults := rule.results
		rule.results = nil
		rule.matched = m.matchingPIDsLocked(rule.definition.Service)
		for _, pid := range rule.matched {
			bound, ready := m.targets[pid]
			var identityErr error
			if ready {
				identity, err := m.identity(pid)
				if err != nil || identity != bound.identity {
					identityErr = ErrTargetGone
				}
			}
			for _, span := range rule.definition.Spans {
				result := m.resultLocked(pid, span.TargetIdentifier(), span.Name)
				if !ready {
					result.Status = "pending"
					rule.results = append(rule.results, result)
					continue
				}
				if identityErr != nil {
					result.Status = "error"
					result.Error = identityErr.Error()
					rule.results = append(rule.results, result)
					continue
				}
				names := []string{span.TargetIdentifier()}
				if span.IsAnyFunction() {
					resolver, ok := bound.tracer.(SymbolResolver)
					var err error
					if !ok {
						err = errors.New("target cannot resolve symbols")
					} else {
						names, err = resolver.ResolveLiveSymbols(app.PID(pid), span.FunctionSymbol())
					}
					if err != nil {
						result.Status = "error"
						result.Error = err.Error()
						rule.results = append(rule.results, result)
						continue
					}
				}
				for _, name := range names {
					key := dynamicKey{pid: pid, function: name}
					concrete := span
					if concrete.IsFunctionSpan() {
						concrete.On.FunctionSpan = name
					} else if concrete.IsFunctionNoRet() {
						concrete.On.FunctionNoRet = name
					}
					result := m.resultLocked(pid, name, concrete.Name)
					if m.suppressed[key] {
						result.Status = "removed"
						rule.results = append(rule.results, result)
						continue
					}
					if prior, exists := desired[key]; exists && !reflect.DeepEqual(prior, concrete) {
						result.Status = "error"
						result.Error = "function already requested with a different span definition"
						rule.results = append(rule.results, result)
						continue
					}
					desired[key] = concrete
					current := m.dynamic[key]
					if current == nil || !reflect.DeepEqual(current.span, concrete) {
						if current == nil && len(m.dynamic) >= m.maxProbes {
							result.Status = "error"
							result.Error = "dynamic probe limit reached"
						} else {
							start, err := m.identity(pid)
							if err == nil && start != bound.identity {
								err = ErrTargetGone
							}
							if err == nil {
								m.nextCookie++
								var probe io.Closer
								probe, err = bound.tracer.AttachLiveSpan(app.PID(pid), bound.ns, &concrete, m.nextCookie, id, 1)
								if err == nil && current != nil {
									err = m.removeDynamicLocked(key)
									if err != nil {
										_ = probe.Close()
									}
								}
								if err == nil {
									result.Status = "attached"
									m.dynamic[key] = &dynamicAttachment{result: result, span: concrete, link: probe, cookie: m.nextCookie}
									m.reportProbe(result, 1)
									m.reportInvocationsLocked(m.nextCookie, pid, name, probe)
								}
							}
							if err != nil {
								result.Status = "error"
								result.Error = err.Error()
							}
						}
					} else {
						result = current.result
					}
					rule.results = append(rule.results, result)
				}
			}
			rule.results = append(rule.results, m.reconcilePatchesLocked(pid, rule, desiredPatches)...)
		}
		if len(rule.results) == 0 {
			rule.results = []ProbeResult{{Status: "pending", Error: "no matching process discovered"}}
		}
		if strings.HasPrefix(id, "config/") {
			for _, result := range rule.results {
				if result.Status == "error" && !slices.Contains(previousResults, result) {
					slog.Warn("dynamic instrumentation rule failed", "rule", id, "pid", result.PID,
						"function", result.Function, "span_name", result.SpanName, "error", result.Error)
				}
			}
		}
		m.rules[id] = rule
	}
	for key := range m.dynamic {
		if _, keep := desired[key]; !keep {
			joined = errors.Join(joined, m.removeDynamicLocked(key))
		}
	}
	return errors.Join(joined, m.removeStalePatchesLocked(desiredPatches))
}

func (m *Manager) resultLocked(pid int, function, name string) ProbeResult {
	service := m.services[pid]
	return ProbeResult{PID: pid, Function: function, SpanName: name, ServiceName: service.Name, ServiceNamespace: service.Namespace}
}

func (m *Manager) removeDynamicLocked(key dynamicKey) error {
	a := m.dynamic[key]
	m.metrics.DynamicProbeInvocations(a.cookie, nil)
	if err := a.link.Close(); err != nil {
		return err
	}
	m.reportProbe(a.result, 0)
	delete(m.dynamic, key)
	return nil
}

func (m *Manager) ListFunctions(criteria services.GlobDefinitionCriteria) []ProbeResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []ProbeResult{}
	for key, a := range m.dynamic {
		if len(criteria) == 0 || (m.matches[key.pid] != nil && m.matches[key.pid](criteria)) {
			out = append(out, a.result)
		}
	}
	slices.SortFunc(out, func(a, b ProbeResult) int {
		if a.PID != b.PID {
			return a.PID - b.PID
		}
		return strings.Compare(a.Function, b.Function)
	})
	return out
}

func (m *Manager) DeleteFunctions(criteria services.GlobDefinitionCriteria, pattern string) error {
	if len(criteria) == 0 {
		return errors.New("service selector is required")
	}
	if err := criteria.Validate(); err != nil {
		return err
	}
	if pattern == "" {
		return errors.New("function is required")
	}
	matcher, err := glob.Compile(pattern)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for key := range m.dynamic {
		if (key.function == pattern || matcher.Match(key.function)) && m.matches[key.pid] != nil && m.matches[key.pid](criteria) {
			if err := m.removeDynamicLocked(key); err != nil {
				return err
			}
			m.suppressed[key] = true
		}
	}
	m.notifyLocked()
	return nil
}

// RuleJSON accepts exactly the same selector and span fields as the YAML configuration.
func RuleJSON(data []byte) (config.DynamicInstrumentationRule, error) {
	var rule config.DynamicInstrumentationRule
	err := decodeRuleJSON(data, &rule)
	return rule, err
}

func (m *Manager) reportProbe(result ProbeResult, value float64) {
	m.metrics.DynamicProbe(result.ServiceName, result.ServiceNamespace, strconv.Itoa(result.PID), result.Function, value)
}

func (m *Manager) reportInvocationsLocked(cookie uint64, pid int, function string, link io.Closer) {
	counter, ok := link.(interface{ Invocations() (uint64, error) })
	if !ok {
		return
	}
	service := m.targets[pid].service
	if service == nil {
		snapshot := svc.Attrs{UID: m.services[pid]}
		service = func() svc.Attrs { return snapshot }
	}
	m.metrics.DynamicProbeInvocations(cookie, &imetrics.DynamicProbeCounter{PID: pid, Function: function, Read: counter.Invocations, Service: service})
}

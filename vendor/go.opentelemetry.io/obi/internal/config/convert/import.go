// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert // import "go.opentelemetry.io/obi/internal/config/convert"

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"unicode/utf8"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	obiconfig "go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/debug"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/transform"
)

var v2AppMetricsFeatureMask = export.AppO11yFeatures |
	export.FeatureApplicationRuntime

var v2NetworkMetricsFeatureMask = export.FeatureNetwork |
	export.FeatureNetworkInterZone |
	export.FeatureNetworkFlowPackets

var v2StatsMetricsFeatureMask = export.FeatureStats

// V2ToRuntime converts a config v2 extension shape into an OBI runtime
// configuration.
func V2ToRuntime(src *schema.Extension) (*obi.Config, error) {
	if err := schema.ValidateStandalone(src); err != nil {
		return nil, err
	}
	_, defaults := RuntimeToV2(nil)
	// Enable Route53 for new v2 configurations without changing v1 migration defaults.
	defaults.Enrich.ServiceName.Sources = []transform.Source{transform.SourceK8s, transform.SourceECS, transform.SourceRoute53}
	// Omitted features retain the protocol and network enablement mapping.
	defaults.Capture.Metrics.Features = nil
	var complete bool
	var err error
	src, complete, err = src.WithDefaults(defaults)
	if err != nil {
		return nil, fmt.Errorf("applying config v2 defaults: %w", err)
	}
	if src.Capture.Telemetry.Metrics.ConnectionInfoTTL.TimeDuration() < 0 {
		return nil, errors.New("capture.telemetry.metrics.connection_info_ttl must not be negative")
	}
	if err := validateV2Channels(src.Capture.Channels); err != nil {
		return nil, err
	}
	if err := validateV2Correlation(src.Correlation, complete); err != nil {
		return nil, err
	}
	policy := effectiveV2CapturePolicy(src.Capture.Policy, src.Capture.Rules, complete)
	if err := validateV2CaptureRules(policy, src.Capture.Rules); err != nil {
		return nil, err
	}
	if err := validateV2RulePatterns(src.Capture.Rules); err != nil {
		return nil, err
	}
	if err := validateV2SignalFilters(src); err != nil {
		return nil, err
	}
	if err := reconcileV2FlowLimitAliases(src); err != nil {
		return nil, err
	}
	if err := validateV2HTTPRoutes(src.Capture.Instrumentation.HTTP.Routes, src.Capture.Rules); err != nil {
		return nil, err
	}
	if err := validateV2HTTPPayloadExtraction(src.Capture.Instrumentation.HTTP.PayloadExtraction); err != nil {
		return nil, err
	}
	if err := validateUnsupportedV2Fields(src); err != nil {
		return nil, err
	}
	if err := validateUnsupportedV2Network(src); err != nil {
		return nil, err
	}
	if err := validateUnsupportedV2Enrichment(src); err != nil {
		return nil, err
	}

	normalized := *src
	normalized.Capture.Instrumentation = instrumentationWithDefaults(src.Capture.Instrumentation)
	src = &normalized

	cfg := runtimeConfigDefaults()
	applyV2Capture(&cfg, src, policy, complete)
	applyV2Standalone(&cfg, src, complete)
	if err := applyV2PeerMetadata(&cfg, src.Enrich, complete); err != nil {
		return nil, err
	}
	if err := applyV2CaptureAttributes(&cfg, src); err != nil {
		return nil, err
	}
	if err := applyV2MetricsEnablement(&cfg, src, complete); err != nil {
		return nil, err
	}
	cfg.Attributes.Select.Normalize()
	if err := cfg.EBPF.LogEnricher.Validate(); err != nil {
		return nil, fmt.Errorf("invalid log trace annotation: %w", err)
	}

	return &cfg, nil
}

func validateV2Channels(channels schema.CaptureChannels) error {
	if channels.BufferLen < 0 {
		return errors.New("capture.channels.buffer_len must be greater than or equal to zero")
	}
	return nil
}

func validateV2Correlation(correlation *schema.Correlation, complete bool) error {
	if correlation == nil {
		return nil
	}
	if err := validateV2LogTraceAnnotationMatch(correlation.LogTraceAnnotation); err != nil {
		return err
	}
	if !complete {
		return nil
	}

	logTrace := correlation.LogTraceAnnotation
	if logTrace.FieldNames.TraceID == nil {
		return errors.New("correlation.log_trace_annotation.field_names.trace_id must not be null")
	}
	if logTrace.FieldNames.SpanID == nil {
		return errors.New("correlation.log_trace_annotation.field_names.span_id must not be null")
	}
	if logTrace.PlainText.Enabled == nil {
		return errors.New("correlation.log_trace_annotation.plain_text.enabled must not be null")
	}
	if logTrace.PlainText.Placement == nil {
		return errors.New("correlation.log_trace_annotation.plain_text.placement must not be null")
	}
	if logTrace.PlainText.Multiline == nil {
		return errors.New("correlation.log_trace_annotation.plain_text.multiline must not be null")
	}
	return nil
}

// The annotated workloads are always a selection: enabling annotation without one is
// an error rather than an implicit "every captured workload"
func validateV2LogTraceAnnotationMatch(logTrace schema.LogTraceAnnotation) error {
	if logTrace.Enabled && len(logTrace.Match) == 0 {
		return errors.New("correlation.log_trace_annotation.match must select at least one workload when enabled")
	}

	for i, match := range logTrace.Match {
		path := fmt.Sprintf("correlation.log_trace_annotation.match[%d]", i)
		if match.Process.ExportsOTLP != nil {
			return fmt.Errorf("%s.process.exports_otlp is not supported", path)
		}
		if ruleMatchEmpty(match) {
			return fmt.Errorf("%s must define a process or kubernetes predicate", path)
		}
		if ruleUsesRegex(match) {
			return fmt.Errorf("%s: regex predicates are not supported, use glob predicates", path)
		}
		if err := validateV2RuleProcessGlobPatterns(path+".process", match.Process); err != nil {
			return err
		}
		if err := validateV2RuleKubernetesGlobPatterns(path+".kubernetes", match.Kubernetes); err != nil {
			return err
		}
	}
	return nil
}

func validateV2HTTPRoutes(routes schema.HTTPRoutes, rules []schema.Rule) error {
	globalPolicies := []struct {
		path   string
		policy *schema.HTTPRoutePolicy
	}{
		{path: "capture.instrumentation.http.routes.incoming", policy: routes.Incoming},
		{path: "capture.instrumentation.http.routes.outgoing", policy: routes.Outgoing},
	}
	for _, routePolicy := range globalPolicies {
		if err := validateV2HTTPRoutePolicy(routePolicy.path, routePolicy.policy); err != nil {
			return err
		}
	}
	for i := range rules {
		if rules[i].Refine.HTTP == nil {
			continue
		}
		refinementPolicies := []struct {
			direction string
			policy    *schema.HTTPRoutePolicy
		}{
			{direction: "incoming", policy: rules[i].Refine.HTTP.Routes.Incoming},
			{direction: "outgoing", policy: rules[i].Refine.HTTP.Routes.Outgoing},
		}
		for _, routePolicy := range refinementPolicies {
			path := fmt.Sprintf("capture.rules[%d].refine.http.routes.%s", i, routePolicy.direction)
			if err := validateV2HTTPRoutePolicy(path, routePolicy.policy); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateV2HTTPRoutePolicy(path string, policy *schema.HTTPRoutePolicy) error {
	if policy == nil {
		return nil
	}
	if policy.Unmatched != nil {
		switch *policy.Unmatched {
		case services.UnmatchUnset, services.UnmatchPath, services.UnmatchWildcard,
			services.UnmatchHeuristic, services.UnmatchLowCardinality:
		default:
			return fmt.Errorf("%s.unmatched has invalid value %q", path, *policy.Unmatched)
		}
	}
	if policy.IgnoreMode != nil {
		switch *policy.IgnoreMode {
		case services.IgnoreMetrics, services.IgnoreTraces, services.IgnoreAll:
		default:
			return fmt.Errorf("%s.ignore_mode has invalid value %q", path, *policy.IgnoreMode)
		}
	}
	if policy.WildcardChar != nil {
		wildcard := *policy.WildcardChar
		if wildcard != "" && (len(wildcard) != 1 || wildcard[0] == 0 || wildcard[0] >= utf8.RuneSelf) {
			return fmt.Errorf("%s.wildcard_char must be empty or contain one nonzero ASCII byte", path)
		}
	}
	if policy.MaxPathSegmentCardinality != nil && *policy.MaxPathSegmentCardinality < 0 {
		return fmt.Errorf("%s.max_path_segment_cardinality must be greater than or equal to zero", path)
	}
	return nil
}

func validateUnsupportedV2Fields(src *schema.Extension) error {
	runtimeFilters := []struct {
		path    string
		filters schema.AttributeFilters
	}{
		{path: "capture.runtimes.go.filter", filters: src.Capture.Runtimes.Go.Filter},
		{path: "capture.runtimes.nodejs.filter", filters: src.Capture.Runtimes.NodeJS.Filter},
		{path: "capture.runtimes.java.filter", filters: src.Capture.Runtimes.Java.Filter},
	}
	for _, runtimeFilter := range runtimeFilters {
		if len(runtimeFilter.filters) != 0 {
			return fmt.Errorf("%s is not supported", runtimeFilter.path)
		}
	}

	if src.Correlation != nil && len(src.Correlation.LogTraceAnnotation.Filter) != 0 {
		return errors.New("correlation.log_trace_annotation.filter is not supported")
	}
	return nil
}

func rejectAdditionalProperties(path string, values map[string]any) error {
	if len(values) == 0 {
		return nil
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return fmt.Errorf("%s.%s is not supported by the runtime converter", path, keys[0])
}

func validateUnsupportedV2Network(src *schema.Extension) error {
	for _, properties := range []struct {
		path   string
		values map[string]any
	}{
		{
			path:   "capture.network.capture",
			values: src.Capture.Network.Capture.AdditionalProperties,
		},
		{
			path:   "capture.network.stats",
			values: src.Capture.Network.Stats.AdditionalProperties,
		},
	} {
		if err := rejectAdditionalProperties(properties.path, properties.values); err != nil {
			return err
		}
	}
	return nil
}

func runtimeConfigDefaults() obi.Config {
	cfg := obi.DefaultConfig
	if cfg.Routes != nil {
		cfg.Routes = cfg.Routes.Clone()
	}
	if cfg.NameResolver != nil {
		nameResolver := *cfg.NameResolver
		cfg.NameResolver = &nameResolver
	}
	return cfg
}

func applyV2Capture(cfg *obi.Config, src *schema.Extension, policy schema.CapturePolicy, complete bool) {
	cfg.Exceptions = src.Capture.Exceptions
	applyV2Policy(cfg, policy, complete || completePolicy(policy))
	hasRuleRoutePolicies := applyV2Rules(cfg, src.Capture.Rules, policy)
	applyV2Limits(cfg, src.Capture.Limits, complete || completeLimits(src.Capture.Limits))
	applyV2Safety(cfg, src.Capture.Safety, complete || !zeroValue(src.Capture.Safety))
	applyV2Channels(cfg, src.Capture.Channels, complete || completeChannels(src.Capture.Channels))
	applyV2Engine(cfg, src.Capture.Engine, complete || completeEngine(src.Capture.Engine))
	applyV2Instrumentation(cfg, src.Capture.Instrumentation, complete)
	if hasRuleRoutePolicies {
		activateV2RuleRoutePolicies(cfg)
	}
	applyV2NetworkCapture(cfg, src.Capture.Network.Capture, complete || completeNetworkCapture(src.Capture.Network.Capture))
	applyV2NetworkStats(cfg, src.Capture.Network.Stats, complete || completeNetworkStats(src.Capture.Network.Stats))
	applyV2Runtimes(cfg, src.Capture.Runtimes, complete || completeRuntimes(src.Capture.Runtimes))
	applyV2CaptureTelemetry(cfg, src.Capture.Telemetry, complete || completeCaptureTelemetry(src.Capture.Telemetry))
}

func applyV2Policy(cfg *obi.Config, policy schema.CapturePolicy, complete bool) {
	if zeroValue(policy) && !complete {
		return
	}

	if complete || completePolicy(policy) {
		cfg.Discovery.PollInterval = policy.PollInterval.TimeDuration()
		cfg.Discovery.MinProcessAge = policy.MinProcessAge.TimeDuration()
		return
	}

	if !zeroValue(policy.PollInterval) {
		cfg.Discovery.PollInterval = policy.PollInterval.TimeDuration()
	}
	if !zeroValue(policy.MinProcessAge) {
		cfg.Discovery.MinProcessAge = policy.MinProcessAge.TimeDuration()
	}
}

type runtimeDiscoveryRules struct {
	includeGlobs                    services.GlobDefinitionCriteria
	excludeGlobs                    services.GlobDefinitionCriteria
	includeRegex                    services.RegexDefinitionCriteria
	excludeRegex                    services.RegexDefinitionCriteria
	hasRoutePolicies                bool
	excludeOTelInstrumentedServices bool
	defaultOTLPGRPCPort             int
}

func applyV2Rules(cfg *obi.Config, rules []schema.Rule, policy schema.CapturePolicy) bool {
	if rules == nil {
		if policy.DefaultAction == schema.CaptureActionInclude {
			cfg.Discovery.Instrument = services.GlobDefinitionCriteria{
				{Path: services.NewGlob("*")},
			}
		}
		return false
	}

	converted := runtimeDiscoveryRulesFromV2(rules, policy.MatchOrder)
	if policy.DefaultAction == schema.CaptureActionInclude {
		addDefaultIncludeSelector(&converted)
	}
	applyRuntimeDiscoveryRules(cfg, converted)
	return converted.hasRoutePolicies
}

func addDefaultIncludeSelector(rules *runtimeDiscoveryRules) {
	if len(rules.includeRegex) > 0 || len(rules.excludeRegex) > 0 {
		rules.includeRegex = slices.Insert(rules.includeRegex, 0, services.RegexSelector{
			Path: services.NewRegexp(".*"),
		})
		return
	}

	rules.includeGlobs = slices.Insert(rules.includeGlobs, 0, services.GlobAttributes{
		Path: services.NewGlob("*"),
	})
}

func runtimeDiscoveryRulesFromV2(rules []schema.Rule, matchOrder schema.MatchOrder) runtimeDiscoveryRules {
	var converted runtimeDiscoveryRules
	completeExports, completeRoutes := completeV2RuleRefinements(rules)
	for _, rule := range rules {
		if collectV2ExportsOTLPExclusionRule(&converted, rule) {
			continue
		}
		globSelector, regexSelector, ok := selectorFromRule(rule, completeExports, completeRoutes)
		if !ok {
			continue
		}

		switch rule.Action {
		case schema.CaptureActionInclude:
			if regexSelector != nil {
				converted.includeRegex = append(converted.includeRegex, *regexSelector)
				converted.hasRoutePolicies = converted.hasRoutePolicies ||
					regexSelector.Routes != nil && regexSelector.Routes.PolicyOverrides != nil
			} else {
				converted.includeGlobs = append(converted.includeGlobs, *globSelector)
				converted.hasRoutePolicies = converted.hasRoutePolicies ||
					globSelector.Routes != nil && globSelector.Routes.PolicyOverrides != nil
			}
		case schema.CaptureActionExclude:
			if regexSelector != nil {
				converted.excludeRegex = append(converted.excludeRegex, *regexSelector)
			} else {
				converted.excludeGlobs = append(converted.excludeGlobs, *globSelector)
			}
		}
	}
	if matchOrder == schema.MatchOrderFirstMatchWins {
		slices.Reverse(converted.includeGlobs)
		slices.Reverse(converted.includeRegex)
	}
	return converted
}

func completeV2RuleRefinements(rules []schema.Rule) (exports, routes bool) {
	includeRules := 0
	for _, rule := range rules {
		if rule.Action != schema.CaptureActionInclude {
			continue
		}
		includeRules++
		exports = exports || rule.Refine.Exports != nil
		routes = routes || rule.Refine.HTTP != nil && !zeroValue(rule.Refine.HTTP.Routes)
	}
	if includeRules < 2 {
		return false, false
	}
	return exports, routes
}

func applyRuntimeDiscoveryRules(cfg *obi.Config, rules runtimeDiscoveryRules) {
	// A present v2 rules section is authoritative for runtime selector state,
	// including the default capture exclusions emitted by RuntimeToV2.
	// ExcludedLinuxSystemPaths only controls language detection, so it retains
	// its runtime default instead of being represented as a capture rule.
	cfg.Discovery.Instrument = rules.includeGlobs
	cfg.Discovery.ExcludeInstrument = rules.excludeGlobs
	cfg.Discovery.DefaultExcludeInstrument = nil
	cfg.Discovery.Services = rules.includeRegex
	cfg.Discovery.ExcludeServices = rules.excludeRegex
	cfg.Discovery.DefaultExcludeServices = nil
	cfg.Discovery.ExcludeOTelInstrumentedServices = rules.excludeOTelInstrumentedServices
	if rules.excludeOTelInstrumentedServices {
		cfg.Discovery.DefaultOtlpGRPCPort = rules.defaultOTLPGRPCPort
	}
}

// The v2 exports_otlp exclusion rule is the exported form of this runtime
// boolean/port pair, not a general selector.
func collectV2ExportsOTLPExclusionRule(rules *runtimeDiscoveryRules, rule schema.Rule) bool {
	if rule.Action != schema.CaptureActionExclude || !ruleMatchOnlyExportsOTLP(rule.Match) {
		return false
	}

	rules.excludeOTelInstrumentedServices = true
	rules.defaultOTLPGRPCPort = rule.Match.Process.ExportsOTLP.Port
	return true
}

func effectiveV2CapturePolicy(
	policy schema.CapturePolicy,
	rules []schema.Rule,
	complete bool,
) schema.CapturePolicy {
	if policy.DefaultAction == "" && !complete {
		policy.DefaultAction = schema.CaptureActionInclude
		for _, rule := range rules {
			if rule.Action == schema.CaptureActionInclude {
				policy.DefaultAction = schema.CaptureActionExclude
				break
			}
		}
	}
	if policy.MatchOrder == "" && !complete {
		policy.MatchOrder = schema.MatchOrderFirstMatchWins
	}
	return policy
}

func validateV2CaptureRules(policy schema.CapturePolicy, rules []schema.Rule) error {
	if policy.DefaultAction != schema.CaptureActionInclude &&
		policy.DefaultAction != schema.CaptureActionExclude {
		return fmt.Errorf("capture.policy.default_action: unsupported value %q", policy.DefaultAction)
	}
	if policy.MatchOrder != schema.MatchOrderFirstMatchWins &&
		policy.MatchOrder != schema.MatchOrderLastMatchWins {
		return fmt.Errorf("capture.policy.match_order: unsupported value %q", policy.MatchOrder)
	}

	var usesGlob, usesRegex bool
	seenInclude := false
	seenExclude := false
	for i, rule := range rules {
		path := fmt.Sprintf("capture.rules[%d]", i)
		if rule.Action != schema.CaptureActionInclude && rule.Action != schema.CaptureActionExclude {
			return fmt.Errorf("%s.action: unsupported value %q", path, rule.Action)
		}
		if err := rejectAdditionalProperties(path, rule.AdditionalProperties); err != nil {
			return err
		}
		if err := rejectAdditionalProperties(path+".match", rule.Match.AdditionalProperties); err != nil {
			return err
		}
		if err := rejectAdditionalProperties(path+".match.process", rule.Match.Process.AdditionalProperties); err != nil {
			return err
		}
		if err := rejectAdditionalProperties(path+".match.kubernetes", rule.Match.Kubernetes.AdditionalProperties); err != nil {
			return err
		}
		if ruleMatchEmpty(rule.Match) {
			return fmt.Errorf("%s.match must define at least one selector", path)
		}
		if rule.Action == schema.CaptureActionExclude && !zeroValue(rule.Refine) {
			return fmt.Errorf("%s.refine is not supported for exclude rules", path)
		}
		if rule.Refine.HTTP != nil && len(rule.Refine.HTTP.Filters.Traces)+len(rule.Refine.HTTP.Filters.Metrics) > 0 {
			return fmt.Errorf("%s.refine.http.filters is not supported by the runtime converter", path)
		}

		if exportsOTLP := rule.Match.Process.ExportsOTLP; exportsOTLP != nil {
			if rule.Action != schema.CaptureActionExclude {
				return fmt.Errorf("%s.match.process.exports_otlp is only supported for exclude rules", path)
			}
			if !ruleMatchOnlyExportsOTLP(rule.Match) {
				return fmt.Errorf("%s.match.process.exports_otlp cannot be combined with other selectors", path)
			}
			if exportsOTLP.Protocol != "protobuf" {
				return fmt.Errorf("%s.match.process.exports_otlp.protocol: unsupported value %q", path, exportsOTLP.Protocol)
			}
			if exportsOTLP.Port < 1 || exportsOTLP.Port > 65535 {
				return fmt.Errorf("%s.match.process.exports_otlp.port: must be between 1 and 65535", path)
			}
		} else {
			glob := ruleUsesGlob(rule.Match)
			regex := ruleUsesRegex(rule.Match)
			if glob && regex {
				return fmt.Errorf("%s.match cannot combine glob and regular-expression selectors", path)
			}
			if regex {
				usesRegex = true
			} else {
				usesGlob = true
			}
			if usesGlob && usesRegex {
				return fmt.Errorf("%s.match cannot mix selector families across capture.rules", path)
			}
		}

		switch rule.Action {
		case schema.CaptureActionInclude:
			if policy.MatchOrder == schema.MatchOrderLastMatchWins && seenExclude {
				return fmt.Errorf("%s.action: last_match_wins cannot preserve runtime exclusion precedence when an include rule follows an exclude rule", path)
			}
			seenInclude = true
		case schema.CaptureActionExclude:
			if policy.MatchOrder == schema.MatchOrderFirstMatchWins && seenInclude {
				return fmt.Errorf("%s.action: first_match_wins cannot preserve runtime exclusion precedence when an exclude rule follows an include rule", path)
			}
			seenExclude = true
		}
	}

	return nil
}

func validateV2RulePatterns(rules []schema.Rule) error {
	for i, rule := range rules {
		path := fmt.Sprintf("capture.rules[%d].match", i)
		if err := validateV2RuleProcessGlobPatterns(path+".process", rule.Match.Process); err != nil {
			return err
		}
		if err := validateV2RuleProcessRegexPatterns(path+".process", rule.Match.Process); err != nil {
			return err
		}
		if err := validateV2RuleKubernetesGlobPatterns(path+".kubernetes", rule.Match.Kubernetes); err != nil {
			return err
		}
		if err := validateV2RuleKubernetesRegexPatterns(path+".kubernetes", rule.Match.Kubernetes); err != nil {
			return err
		}
	}
	return nil
}

func validateV2SignalFilters(src *schema.Extension) error {
	if err := validateSharedSignalFilters(
		"capture.network.capture.filters",
		"network",
		src.Capture.Network.Capture.Filters,
	); err != nil {
		return err
	}
	return validateSharedSignalFilters(
		"capture.network.stats.filters",
		"network stats",
		src.Capture.Network.Stats.Filters,
	)
}

func validateSharedSignalFilters(path, runtimeFilter string, filters schema.SignalFilters) error {
	return validateSharedAttributeFilters(
		path+".metrics",
		path+".traces",
		runtimeFilter,
		filters.Metrics,
		filters.Traces,
	)
}

func validateSharedAttributeFilters(
	path string,
	canonicalPath string,
	runtimeFilter string,
	filters schema.AttributeFilters,
	canonical schema.AttributeFilters,
) error {
	if attributeFiltersEqual(filters, canonical) {
		return nil
	}
	return fmt.Errorf(
		"%s cannot differ from %s because the runtime uses one %s filter",
		path,
		canonicalPath,
		runtimeFilter,
	)
}

func attributeFiltersEqual(left, right schema.AttributeFilters) bool {
	if len(left) == 0 && len(right) == 0 {
		return true
	}
	return reflect.DeepEqual(left, right)
}

func reconcileV2FlowLimitAliases(src *schema.Extension) error {
	networkPackets := src.Capture.Limits.NetworkPackets
	maxTrackedFlows := src.Capture.Network.Capture.FlowLifecycle.MaxTrackedFlows
	networkPacketsSet, maxTrackedFlowsSet, presenceKnown := src.FlowLimitAliasPresence()

	if presenceKnown {
		if networkPacketsSet && networkPackets < 1 {
			return errors.New("capture.limits.network_packets must be greater than zero")
		}
		if maxTrackedFlowsSet && maxTrackedFlows < 1 {
			return errors.New(
				"capture.network.capture.flow_lifecycle.max_tracked_flows must be greater than zero",
			)
		}

		switch {
		case networkPacketsSet && !maxTrackedFlowsSet:
			if networkPackets != 0 {
				src.Capture.Network.Capture.FlowLifecycle.MaxTrackedFlows = networkPackets
			} else if maxTrackedFlows != 0 {
				src.Capture.Limits.NetworkPackets = maxTrackedFlows
			}
			return nil
		case !networkPacketsSet && maxTrackedFlowsSet:
			if maxTrackedFlows != 0 {
				src.Capture.Limits.NetworkPackets = maxTrackedFlows
			} else if networkPackets != 0 {
				src.Capture.Network.Capture.FlowLifecycle.MaxTrackedFlows = networkPackets
			}
			return nil
		case !networkPacketsSet && !maxTrackedFlowsSet:
			return nil
		}
	}

	switch {
	case networkPackets == 0 && maxTrackedFlows == 0:
		return nil
	case networkPackets == 0:
		src.Capture.Limits.NetworkPackets = maxTrackedFlows
		return nil
	case maxTrackedFlows == 0:
		src.Capture.Network.Capture.FlowLifecycle.MaxTrackedFlows = networkPackets
		return nil
	case networkPackets == maxTrackedFlows:
		return nil
	}

	return fmt.Errorf(
		"capture.limits.network_packets (%d) must equal "+
			"capture.network.capture.flow_lifecycle.max_tracked_flows (%d): "+
			"both configure network.cache_max_flows",
		networkPackets,
		maxTrackedFlows,
	)
}

func validateV2HTTPPayloadExtraction(payload schema.PayloadExtraction) error {
	for i, extractor := range payload.Enabled {
		if !validV2HTTPPayloadExtractor(extractor) {
			return fmt.Errorf(
				"capture.instrumentation.http.payload_extraction.enabled[%d]: unknown payload extractor %q",
				i,
				extractor,
			)
		}
	}
	return nil
}

func validV2HTTPPayloadExtractor(extractor string) bool {
	switch extractor {
	case payloadExtractorGraphQL,
		payloadExtractorElasticsearch,
		payloadExtractorAWS,
		payloadExtractorSQLPP,
		payloadExtractorOpenAI,
		payloadExtractorAnthropic,
		payloadExtractorGemini,
		payloadExtractorQwen,
		payloadExtractorBedrock,
		payloadExtractorMCP,
		payloadExtractorOllama,
		payloadExtractorCohere,
		payloadExtractorOpenAICompatible,
		payloadExtractorEmbedding,
		payloadExtractorRerank,
		payloadExtractorRetrieval,
		payloadExtractorJSONRPC,
		payloadExtractorEnrichment:
		return true
	default:
		return false
	}
}

func validateV2RuleProcessGlobPatterns(path string, match schema.RuleProcessMatch) error {
	if err := validateGlobAttr(path+".language_glob", match.LanguageGlob); err != nil {
		return err
	}
	if err := validateGlobAttr(path+".cmd_args_glob", match.CmdArgsGlob); err != nil {
		return err
	}
	return validateGlobAttr(path+".exe_path_glob", match.ExePathGlob)
}

func validateV2RuleProcessRegexPatterns(path string, match schema.RuleProcessMatch) error {
	if err := validateRegexpAttr(path+".language_regex", match.LanguageRegex); err != nil {
		return err
	}
	if err := validateRegexpAttr(path+".cmd_args_regex", match.CmdArgsRegex); err != nil {
		return err
	}
	return validateRegexpAttr(path+".exe_path_regex", match.ExePathRegex)
}

func validateV2RuleKubernetesGlobPatterns(path string, match schema.RuleKubernetesMatch) error {
	if err := validateGlobAttr(path+".namespace_glob", match.NamespaceGlob); err != nil {
		return err
	}
	if err := validateGlobAttrMap(path+".metadata_glob", match.MetadataGlob); err != nil {
		return err
	}
	if err := validateGlobAttrMap(path+".pod_labels", match.PodLabels); err != nil {
		return err
	}
	return validateGlobAttrMap(path+".pod_annotations", match.PodAnnotations)
}

func validateV2RuleKubernetesRegexPatterns(path string, match schema.RuleKubernetesMatch) error {
	if err := validateRegexpAttr(path+".namespace_regex", match.NamespaceRegex); err != nil {
		return err
	}
	if err := validateRegexpAttrMap(path+".metadata_regex", match.MetadataRegex); err != nil {
		return err
	}
	if err := validateRegexpAttrMap(path+".pod_labels_regex", match.PodLabelsRegex); err != nil {
		return err
	}
	return validateRegexpAttrMap(path+".pod_annotations_regex", match.PodAnnotationsRegex)
}

func validateGlobAttr(path string, values []string) error {
	if len(values) == 0 {
		return nil
	}
	var attr services.GlobAttr
	pattern := globPattern(values)
	if err := attr.UnmarshalText([]byte(pattern)); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func validateGlobAttrMap(path string, values map[string][]string) error {
	for key, value := range values {
		if err := validateGlobAttr(fmt.Sprintf("%s[%q]", path, key), value); err != nil {
			return err
		}
	}
	return nil
}

func validateRegexpAttr(path, value string) error {
	if value == "" {
		return nil
	}
	var attr services.RegexpAttr
	if err := attr.UnmarshalText([]byte(value)); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func validateRegexpAttrMap(path string, values map[string]string) error {
	for key, value := range values {
		if err := validateRegexpAttr(fmt.Sprintf("%s[%q]", path, key), value); err != nil {
			return err
		}
	}
	return nil
}

func selectorFromRule(
	rule schema.Rule,
	completeExports bool,
	completeRoutes bool,
) (*services.GlobAttributes, *services.RegexSelector, bool) {
	if rule.Match.Process.ExportsOTLP != nil || ruleMatchEmpty(rule.Match) {
		return nil, nil, false
	}

	if ruleUsesRegex(rule.Match) {
		if ruleUsesGlob(rule.Match) {
			return nil, nil, false
		}
		selector := regexSelectorFromRule(rule)
		selector.Exceptions = rule.Refine.Exceptions
		selector.ExportModes, selector.Routes = v2RuleRefinement(
			rule.Refine,
			completeExports,
			completeRoutes,
		)
		return nil, &selector, true
	}

	selector := globSelectorFromRule(rule)
	selector.Exceptions = rule.Refine.Exceptions
	selector.ExportModes, selector.Routes = v2RuleRefinement(
		rule.Refine,
		completeExports,
		completeRoutes,
	)
	return &selector, nil, true
}

func ruleMatchOnlyExportsOTLP(match schema.RuleMatch) bool {
	if match.Process.ExportsOTLP == nil {
		return false
	}
	match.Process.ExportsOTLP = nil
	return ruleMatchEmpty(match)
}

func ruleUsesRegex(match schema.RuleMatch) bool {
	return match.Process.LanguageRegex != "" ||
		match.Process.CmdArgsRegex != "" ||
		match.Process.ExePathRegex != "" ||
		match.Kubernetes.NamespaceRegex != "" ||
		len(match.Kubernetes.MetadataRegex) > 0 ||
		len(match.Kubernetes.PodLabelsRegex) > 0 ||
		len(match.Kubernetes.PodAnnotationsRegex) > 0
}

func ruleUsesGlob(match schema.RuleMatch) bool {
	return len(match.Process.LanguageGlob) > 0 ||
		len(match.Process.CmdArgsGlob) > 0 ||
		len(match.Process.ExePathGlob) > 0 ||
		len(match.Kubernetes.NamespaceGlob) > 0 ||
		len(match.Kubernetes.MetadataGlob) > 0 ||
		len(match.Kubernetes.PodLabels) > 0 ||
		len(match.Kubernetes.PodAnnotations) > 0
}

func globSelectorFromRule(rule schema.Rule) services.GlobAttributes {
	return globSelectorFromMatch(rule.Match)
}

func globSelectorFromMatch(match schema.RuleMatch) services.GlobAttributes {
	return services.GlobAttributes{
		OpenPorts:      intEnumValue(match.Process.OpenPorts),
		PIDs:           slices.Clone(match.Process.TargetPIDs),
		Languages:      globAttr(match.Process.LanguageGlob),
		CmdArgs:        globAttr(match.Process.CmdArgsGlob),
		Path:           globAttr(match.Process.ExePathGlob),
		ContainersOnly: match.Process.ContainersOnly,
		Metadata:       globMetadata(match.Kubernetes),
		PodLabels:      globAttrMap(match.Kubernetes.PodLabels),
		PodAnnotations: globAttrMap(match.Kubernetes.PodAnnotations),
	}
}

func regexSelectorFromRule(rule schema.Rule) services.RegexSelector {
	match := rule.Match
	return services.RegexSelector{
		OpenPorts:      intEnumValue(match.Process.OpenPorts),
		PIDs:           slices.Clone(match.Process.TargetPIDs),
		Languages:      regexpAttr(match.Process.LanguageRegex),
		CmdArgs:        regexpAttr(match.Process.CmdArgsRegex),
		Path:           regexpAttr(match.Process.ExePathRegex),
		ContainersOnly: match.Process.ContainersOnly,
		Metadata:       regexMetadata(match.Kubernetes),
		PodLabels:      regexpAttrMap(match.Kubernetes.PodLabelsRegex),
		PodAnnotations: regexpAttrMap(match.Kubernetes.PodAnnotationsRegex),
	}
}

func v2RuleRefinement(
	refine schema.RuleRefinement,
	completeExports bool,
	completeRoutes bool,
) (services.ExportModes, *services.CustomRoutesConfig) {
	var exports services.ExportModes
	if refine.Exports != nil {
		exports = exportModesFromRefinement(*refine.Exports)
	} else if completeExports {
		exports = explicitAllowAllExportModes()
	}

	var routes *services.CustomRoutesConfig
	if refine.HTTP != nil && !zeroValue(refine.HTTP.Routes) {
		routes = &services.CustomRoutesConfig{
			PolicyOverrides: v2DirectionalRoutePolicyOverrides(refine.HTTP.Routes),
		}
	} else if completeRoutes {
		routes = &services.CustomRoutesConfig{}
	}
	return exports, routes
}

func explicitAllowAllExportModes() services.ExportModes {
	modes := services.NewExportModes()
	modes.AllowTraces()
	modes.AllowMetrics()
	modes.AllowLogs()
	return modes
}

func v2DirectionalRoutePolicyOverrides(routes schema.HTTPRefinementRoutes) *services.DirectionalRoutePolicyOverrides {
	return &services.DirectionalRoutePolicyOverrides{
		Incoming: v2RoutePolicyOverride(routes.Incoming),
		Outgoing: v2RoutePolicyOverride(routes.Outgoing),
	}
}

func v2RoutePolicyOverride(policy *schema.HTTPRoutePolicy) *services.RoutePolicyOverride {
	if policy == nil {
		return nil
	}
	return &services.RoutePolicyOverride{
		Unmatch:                   cloneValue(policy.Unmatched),
		Patterns:                  cloneStringsPointer(policy.Patterns),
		IgnorePatterns:            cloneStringsPointer(policy.IgnoredPatterns),
		IgnoredEvents:             cloneValue(policy.IgnoreMode),
		WildcardChar:              cloneValue(policy.WildcardChar),
		MaxPathSegmentCardinality: cloneValue(policy.MaxPathSegmentCardinality),
	}
}

func exportModesFromRefinement(refine schema.ExportModeRefinement) services.ExportModes {
	modes := services.NewExportModes()
	if refine.Logs {
		modes.AllowLogs()
	}
	if refine.Traces {
		modes.AllowTraces()
	}
	if refine.Metrics {
		modes.AllowMetrics()
	}
	return modes
}

func intEnumValue(in *services.IntEnum) services.IntEnum {
	if in == nil {
		return services.IntEnum{}
	}
	return *in
}

func globAttr(values []string) services.GlobAttr {
	switch len(values) {
	case 0:
		return services.GlobAttr{}
	default:
		return services.NewGlob(globPattern(values))
	}
}

func globPattern(values []string) string {
	if len(values) == 1 {
		return values[0]
	}
	return "{" + strings.Join(values, ",") + "}"
}

func globAttrMap(values map[string][]string) map[string]*services.GlobAttr {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]*services.GlobAttr, len(values))
	for key, value := range values {
		attr := globAttr(value)
		out[key] = &attr
	}
	return out
}

func globMetadata(match schema.RuleKubernetesMatch) services.MetadataGlobMap {
	out := globAttrMap(match.MetadataGlob)
	if out == nil {
		out = services.MetadataGlobMap{}
	}
	if len(match.NamespaceGlob) > 0 {
		attr := globAttr(match.NamespaceGlob)
		out[services.AttrNamespace] = &attr
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func regexpAttr(value string) services.RegexpAttr {
	if value == "" {
		return services.RegexpAttr{}
	}
	return services.NewRegexp(value)
}

func regexpAttrMap(values map[string]string) map[string]*services.RegexpAttr {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]*services.RegexpAttr, len(values))
	for key, value := range values {
		attr := regexpAttr(value)
		out[key] = &attr
	}
	return out
}

func regexMetadata(match schema.RuleKubernetesMatch) services.MetadataRegexMap {
	out := regexpAttrMap(match.MetadataRegex)
	if out == nil {
		out = services.MetadataRegexMap{}
	}
	if match.NamespaceRegex != "" {
		attr := regexpAttr(match.NamespaceRegex)
		out[services.AttrNamespace] = &attr
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func applyV2Limits(cfg *obi.Config, limits schema.CaptureLimits, complete bool) {
	if zeroValue(limits) && !complete {
		return
	}

	if complete || completeLimits(limits) {
		cfg.Attributes.MetricSpanNameAggregationLimit = limits.MetricSpanNames
		cfg.NetworkFlows.CacheMaxFlows = limits.NetworkPackets
		return
	}

	if limits.MetricSpanNames != 0 {
		cfg.Attributes.MetricSpanNameAggregationLimit = limits.MetricSpanNames
	}
	if limits.NetworkPackets != 0 {
		cfg.NetworkFlows.CacheMaxFlows = limits.NetworkPackets
	}
}

func applyV2Safety(cfg *obi.Config, safety schema.CaptureSafety, complete bool) {
	if zeroValue(safety) && !complete {
		return
	}

	if complete {
		cfg.EnforceSysCaps = safety.EnforceSystemCapabilities
		return
	}

	if safety.EnforceSystemCapabilities {
		cfg.EnforceSysCaps = true
	}
}

func applyV2Channels(cfg *obi.Config, channels schema.CaptureChannels, complete bool) {
	if zeroValue(channels) && !complete {
		return
	}

	if complete || completeChannels(channels) {
		cfg.ChannelBufferLen = channels.BufferLen
		cfg.ChannelSendTimeout = channels.SendTimeout.TimeDuration()
		cfg.ChannelSendTimeoutPanic = channels.PanicOnSendTimeout
		return
	}

	if channels.BufferLen != 0 {
		cfg.ChannelBufferLen = channels.BufferLen
	}
	if !zeroValue(channels.SendTimeout) {
		cfg.ChannelSendTimeout = channels.SendTimeout.TimeDuration()
	}
	if channels.PanicOnSendTimeout {
		cfg.ChannelSendTimeoutPanic = true
	}
}

func applyV2Engine(cfg *obi.Config, engine schema.CaptureEngine, complete bool) {
	if zeroValue(engine) && !complete {
		return
	}

	if complete || completeEngine(engine) {
		applyFullV2Engine(cfg, engine)
		return
	}

	applyPartialV2Engine(cfg, engine)
}

func applyFullV2Engine(cfg *obi.Config, engine schema.CaptureEngine) {
	cfg.EBPF.BpfDebug = engine.Debug.BPF
	cfg.EBPF.ProtocolDebug = engine.Debug.ProtocolPrint
	cfg.Discovery.BPFPidFilterOff = engine.PIDFilter.Disabled
	cfg.EBPF.WakeupLen = engine.Batching.WakeupLen
	cfg.EBPF.BatchLength = engine.Batching.BatchLength
	cfg.EBPF.BatchTimeout = engine.Batching.BatchTimeout.TimeDuration()
	cfg.EBPF.ContextPropagation = engine.Propagation.ContextPropagation
	cfg.EBPF.OverrideBPFLoopEnabled = engine.Propagation.OverrideBPFLoopEnabled
	cfg.EBPF.DisableBlackBoxCP = engine.Propagation.DisableBlackBoxCP
	cfg.EBPF.PopulateTraceContext = engine.Propagation.PopulateTraceContext
	cfg.EBPF.TCBackend = engine.Traffic.ControlBackend
	cfg.EBPF.HighRequestVolume = engine.Traffic.HighRequestVolume
	cfg.EBPF.ForceBPFMapReader = engine.Traffic.ForceMapReader
	cfg.EBPF.MaxTransactionTime = engine.Transactions.MaxDuration.TimeDuration()
	cfg.EBPF.MapsConfig.GlobalScaleFactor = engine.Maps.GlobalScaleFactor
	cfg.EBPF.BPFFSPath = engine.BPFFileSystem.Path
	cfg.EBPF.CgroupFSPath = engine.CgroupFileSystem.Path
}

func applyPartialV2Engine(cfg *obi.Config, engine schema.CaptureEngine) {
	if engine.Debug.BPF {
		cfg.EBPF.BpfDebug = true
	}
	if engine.Debug.ProtocolPrint {
		cfg.EBPF.ProtocolDebug = true
	}
	if engine.PIDFilter.Disabled {
		cfg.Discovery.BPFPidFilterOff = true
	}
	if engine.Batching.WakeupLen != 0 {
		cfg.EBPF.WakeupLen = engine.Batching.WakeupLen
	}
	if engine.Batching.BatchLength != 0 {
		cfg.EBPF.BatchLength = engine.Batching.BatchLength
	}
	if !zeroValue(engine.Batching.BatchTimeout) {
		cfg.EBPF.BatchTimeout = engine.Batching.BatchTimeout.TimeDuration()
	}
	if !zeroValue(engine.Propagation.ContextPropagation) {
		cfg.EBPF.ContextPropagation = engine.Propagation.ContextPropagation
	}
	if engine.Propagation.OverrideBPFLoopEnabled {
		cfg.EBPF.OverrideBPFLoopEnabled = true
	}
	if engine.Propagation.DisableBlackBoxCP {
		cfg.EBPF.DisableBlackBoxCP = true
	}
	if engine.Propagation.PopulateTraceContext {
		cfg.EBPF.PopulateTraceContext = true
	}
	if !zeroValue(engine.Traffic.ControlBackend) {
		cfg.EBPF.TCBackend = engine.Traffic.ControlBackend
	}
	if engine.Traffic.HighRequestVolume {
		cfg.EBPF.HighRequestVolume = true
	}
	if !zeroValue(engine.Traffic.ForceMapReader) {
		cfg.EBPF.ForceBPFMapReader = engine.Traffic.ForceMapReader
	}
	if !zeroValue(engine.Transactions.MaxDuration) {
		cfg.EBPF.MaxTransactionTime = engine.Transactions.MaxDuration.TimeDuration()
	}
	if engine.Maps.GlobalScaleFactor != 0 {
		cfg.EBPF.MapsConfig.GlobalScaleFactor = engine.Maps.GlobalScaleFactor
	}
	if engine.BPFFileSystem.Path != "" {
		cfg.EBPF.BPFFSPath = engine.BPFFileSystem.Path
	}
	if engine.CgroupFileSystem.Path != "" {
		cfg.EBPF.CgroupFSPath = engine.CgroupFileSystem.Path
	}
}

func instrumentationWithDefaults(instrumentation schema.Instrumentation) schema.Instrumentation {
	if !completeInstrumentationWithoutAerospike(instrumentation) || instrumentation.Aerospike != nil {
		return instrumentation
	}

	aerospike := schema.AerospikeInstrumentation{
		Enabled: schema.ProtocolEnablement{Traces: true, Metrics: true},
	}
	instrumentation.Aerospike = &aerospike
	return instrumentation
}

func applyV2Instrumentation(cfg *obi.Config, instrumentation schema.Instrumentation, complete bool) {
	if zeroValue(instrumentation) && !complete {
		return
	}

	applyV2InstrumentationFilters(cfg, instrumentation)

	complete = complete || completeInstrumentation(instrumentation)
	if !complete {
		applyPartialV2Instrumentation(cfg, instrumentation)
		applyProtocolEnablement(cfg, instrumentation, complete)
		return
	}

	applyFullV2Instrumentation(cfg, instrumentation)
	applyProtocolEnablement(cfg, instrumentation, complete)
}

func applyFullV2Instrumentation(cfg *obi.Config, instrumentation schema.Instrumentation) {
	applyFullV2HTTPInstrumentation(cfg, instrumentation.HTTP)

	cfg.EBPF.HeuristicSQLDetect = instrumentation.SQL.HeuristicDetect
	cfg.Attributes.SanitizeSQLQueryText = instrumentation.SQL.SanitizeQueryText
	cfg.EBPF.BufferSizes.MySQL = instrumentation.SQL.MySQL.BufferSize
	cfg.EBPF.MySQLPreparedStatementsCacheSize = instrumentation.SQL.MySQL.PreparedStatementsCacheSize
	cfg.EBPF.BufferSizes.Postgres = instrumentation.SQL.Postgres.BufferSize
	cfg.EBPF.PostgresPreparedStatementsCacheSize = instrumentation.SQL.Postgres.PreparedStatementsCacheSize
	cfg.EBPF.BufferSizes.MSSQL = instrumentation.SQL.MSSQL.BufferSize
	cfg.EBPF.MSSQLPreparedStatementsCacheSize = instrumentation.SQL.MSSQL.PreparedStatementsCacheSize

	cfg.EBPF.RedisDBCache.Enabled = instrumentation.Redis.DBCache.Enabled
	cfg.EBPF.RedisDBCache.MaxSize = instrumentation.Redis.DBCache.MaxSize

	cfg.EBPF.BufferSizes.Kafka = instrumentation.Kafka.BufferSize
	cfg.EBPF.KafkaTopicUUIDCacheSize = instrumentation.Kafka.TopicUUIDCacheSize

	if instrumentation.Aerospike != nil {
		cfg.EBPF.BufferSizes.Aerospike = instrumentation.Aerospike.BufferSize
	}

	cfg.EBPF.MongoRequestsCacheSize = instrumentation.Mongo.RequestsCacheSize
	cfg.EBPF.CouchbaseDBCacheSize = instrumentation.Couchbase.DBCacheSize
	cfg.EBPF.DNSRequestTimeout = instrumentation.DNS.RequestTimeout.TimeDuration()
	cfg.EBPF.InstrumentCuda = instrumentation.GPU.EnabledMode
}

func applyPartialV2Instrumentation(cfg *obi.Config, instrumentation schema.Instrumentation) {
	if !zeroValue(instrumentation.HTTP) {
		applyPartialV2HTTPInstrumentation(cfg, instrumentation.HTTP)
	}

	if !zeroValue(instrumentation.SQL) {
		if instrumentation.SQL.HeuristicDetect {
			cfg.EBPF.HeuristicSQLDetect = true
		}
		if instrumentation.SQL.SanitizeQueryText {
			cfg.Attributes.SanitizeSQLQueryText = true
		}
		if instrumentation.SQL.MySQL.BufferSize != 0 {
			cfg.EBPF.BufferSizes.MySQL = instrumentation.SQL.MySQL.BufferSize
		}
		if instrumentation.SQL.MySQL.PreparedStatementsCacheSize != 0 {
			cfg.EBPF.MySQLPreparedStatementsCacheSize = instrumentation.SQL.MySQL.PreparedStatementsCacheSize
		}
		if instrumentation.SQL.Postgres.BufferSize != 0 {
			cfg.EBPF.BufferSizes.Postgres = instrumentation.SQL.Postgres.BufferSize
		}
		if instrumentation.SQL.Postgres.PreparedStatementsCacheSize != 0 {
			cfg.EBPF.PostgresPreparedStatementsCacheSize = instrumentation.SQL.Postgres.PreparedStatementsCacheSize
		}
		if instrumentation.SQL.MSSQL.BufferSize != 0 {
			cfg.EBPF.BufferSizes.MSSQL = instrumentation.SQL.MSSQL.BufferSize
		}
		if instrumentation.SQL.MSSQL.PreparedStatementsCacheSize != 0 {
			cfg.EBPF.MSSQLPreparedStatementsCacheSize = instrumentation.SQL.MSSQL.PreparedStatementsCacheSize
		}
	}

	if !zeroValue(instrumentation.Redis.DBCache) {
		if instrumentation.Redis.DBCache.Enabled {
			cfg.EBPF.RedisDBCache.Enabled = true
		}
		if instrumentation.Redis.DBCache.MaxSize != 0 {
			cfg.EBPF.RedisDBCache.MaxSize = instrumentation.Redis.DBCache.MaxSize
		}
	}

	if instrumentation.Kafka.BufferSize != 0 {
		cfg.EBPF.BufferSizes.Kafka = instrumentation.Kafka.BufferSize
	}
	if instrumentation.Kafka.TopicUUIDCacheSize != 0 {
		cfg.EBPF.KafkaTopicUUIDCacheSize = instrumentation.Kafka.TopicUUIDCacheSize
	}
	if instrumentation.Aerospike != nil && instrumentation.Aerospike.BufferSize != 0 {
		cfg.EBPF.BufferSizes.Aerospike = instrumentation.Aerospike.BufferSize
	}
	if instrumentation.Mongo.RequestsCacheSize != 0 {
		cfg.EBPF.MongoRequestsCacheSize = instrumentation.Mongo.RequestsCacheSize
	}
	if instrumentation.Couchbase.DBCacheSize != 0 {
		cfg.EBPF.CouchbaseDBCacheSize = instrumentation.Couchbase.DBCacheSize
	}
	if !zeroValue(instrumentation.DNS.RequestTimeout) {
		cfg.EBPF.DNSRequestTimeout = instrumentation.DNS.RequestTimeout.TimeDuration()
	}
	if !zeroValue(instrumentation.GPU.EnabledMode) {
		cfg.EBPF.InstrumentCuda = instrumentation.GPU.EnabledMode
	}
}

func applyFullV2HTTPInstrumentation(cfg *obi.Config, http schema.HTTPInstrumentation) {
	cfg.EBPF.TrackRequestHeaders = http.TrackRequestHeaders
	cfg.EBPF.HTTPRequestTimeout = http.RequestTimeout.TimeDuration()
	cfg.EBPF.GoHTTPClientBufferTimeout = http.GoHTTPClientBufferTimeout.TimeDuration()
	cfg.EBPF.BufferSizes.HTTP = http.BufferSize

	applyFullV2HTTPRoutes(cfg, http.Routes)
	applyFullV2HTTPPayloadExtraction(cfg, http.PayloadExtraction)
}

func applyPartialV2HTTPInstrumentation(cfg *obi.Config, http schema.HTTPInstrumentation) {
	if http.TrackRequestHeaders {
		cfg.EBPF.TrackRequestHeaders = true
	}
	if !zeroValue(http.RequestTimeout) {
		cfg.EBPF.HTTPRequestTimeout = http.RequestTimeout.TimeDuration()
	}
	if !zeroValue(http.GoHTTPClientBufferTimeout) {
		cfg.EBPF.GoHTTPClientBufferTimeout = http.GoHTTPClientBufferTimeout.TimeDuration()
	}
	if http.BufferSize != 0 {
		cfg.EBPF.BufferSizes.HTTP = http.BufferSize
	}
	applyPartialV2HTTPRoutes(cfg, http.Routes)
	applyPartialV2HTTPPayloadExtraction(cfg, http.PayloadExtraction)
}

func applyV2InstrumentationFilters(cfg *obi.Config, instrumentation schema.Instrumentation) {
	for _, mapping := range protocolMappings {
		filters := protocolFilters(instrumentation, mapping.name)
		runtimeFilters := filter.SignalAttributeFamilyConfig{
			Traces:  attributeFilterMap(filters.Traces),
			Metrics: attributeFilterMap(filters.Metrics),
		}
		if len(runtimeFilters.Traces) == 0 && len(runtimeFilters.Metrics) == 0 {
			continue
		}
		if cfg.Filters.ApplicationByInstrumentation == nil {
			cfg.Filters.ApplicationByInstrumentation = filter.InstrumentationAttributeFamilyConfig{}
		}
		cfg.Filters.ApplicationByInstrumentation[mapping.instr] = runtimeFilters
	}
}

func applyFullV2HTTPRoutes(cfg *obi.Config, routes schema.HTTPRoutes) {
	applyV2HTTPRouteDiscovery(cfg, routes.Discovery, true)
	if !hasV2HTTPGlobalRouteConfig(routes) {
		cfg.Routes = nil
		return
	}

	policies := services.DirectionalRoutePolicies{}
	applyV2HTTPRouteConfig(&policies, routes)
	// A v1 global routes block exports identical incoming/outgoing policies.
	// Collapse them back into a single global RoutesConfig so migrations round-trip
	// to the representation the user authored instead of a directional one.
	if routes.Incoming != nil && routes.Outgoing != nil &&
		reflect.DeepEqual(policies.Incoming, policies.Outgoing) {
		cfg.Routes = globalRoutesConfig(policies.Incoming)
		return
	}
	cfg.Routes = &transform.RoutesConfig{
		Directional: &policies,
		DirectionalPolicyPresence: &transform.DirectionalRoutePolicyPresence{
			Incoming: routes.Incoming != nil,
			Outgoing: routes.Outgoing != nil,
		},
	}
}

func globalRoutesConfig(policy services.RoutePolicy) *transform.RoutesConfig {
	return &transform.RoutesConfig{
		Unmatch:                   transform.UnmatchType(policy.Unmatch),
		Patterns:                  cloneStrings(policy.Patterns),
		IgnorePatterns:            cloneStrings(policy.IgnorePatterns),
		IgnoredEvents:             transform.IgnoreMode(policy.IgnoredEvents),
		WildcardChar:              policy.WildcardChar,
		MaxPathSegmentCardinality: policy.MaxPathSegmentCardinality,
	}
}

func applyPartialV2HTTPRoutes(cfg *obi.Config, routes schema.HTTPRoutes) {
	if zeroValue(routes) {
		return
	}
	applyV2HTTPRouteDiscovery(cfg, routes.Discovery, false)
	if !hasV2HTTPGlobalRouteConfig(routes) {
		return
	}
	policies := cfg.Routes.DirectionalPolicies()
	applyV2HTTPRouteConfig(&policies, routes)
	cfg.Routes = &transform.RoutesConfig{Directional: &policies}
}

func applyV2HTTPRouteDiscovery(cfg *obi.Config, discovery schema.HTTPRouteDiscovery, complete bool) {
	if zeroValue(discovery) && !complete {
		return
	}
	if complete || !zeroValue(discovery.Timeout) {
		cfg.Discovery.RouteHarvesterTimeout = discovery.Timeout.TimeDuration()
	}
	if complete || discovery.DisabledLanguages != nil {
		cfg.Discovery.DisabledRouteHarvesters = cloneRouteHarvesterLanguages(discovery.DisabledLanguages)
	}
	if complete || !zeroValue(discovery.Java.Delay) {
		cfg.Discovery.RouteHarvestConfig.JavaHarvestDelay = discovery.Java.Delay.TimeDuration()
	}
}

func hasV2HTTPGlobalRouteConfig(routes schema.HTTPRoutes) bool {
	return routes.Incoming != nil || routes.Outgoing != nil
}

func activateV2RuleRoutePolicies(cfg *obi.Config) {
	ruleOnly := cfg.Routes == nil
	policies := cfg.Routes.DirectionalPolicies()
	// Directions without a global policy use an inactive baseline so a
	// refinement containing only patterns does not inherit wildcard behavior.
	if !cfg.Routes.HasIncomingPolicy() {
		policies.Incoming.Unmatch = services.UnmatchUnset
	}
	if !cfg.Routes.HasOutgoingPolicy() {
		policies.Outgoing.Unmatch = services.UnmatchUnset
	}
	if ruleOnly {
		cfg.Routes = &transform.RoutesConfig{}
	}
	cfg.Routes.Directional = &policies
	cfg.Routes.DirectionalRuleOnly = ruleOnly
}

func applyV2HTTPRouteConfig(dst *services.DirectionalRoutePolicies, routes schema.HTTPRoutes) {
	dst.Incoming = v2RoutePolicyOverride(routes.Incoming).Apply(dst.Incoming)
	dst.Outgoing = v2RoutePolicyOverride(routes.Outgoing).Apply(dst.Outgoing)
}

func applyFullV2HTTPPayloadExtraction(cfg *obi.Config, payload schema.PayloadExtraction) {
	http := &cfg.EBPF.PayloadExtraction.HTTP
	applyV2HTTPPayloadExtractorMembership(http, payload.Enabled)
	http.SQLPP.EndpointPatterns = cloneStrings(payload.SQLPP.EndpointPatterns)
	http.SQLPP.PreparedStatementsCacheSize = payload.SQLPP.PreparedStatementsCacheSize
	http.GenAI.OpenAICompatible.Gateways = payload.OpenAICompatible.Gateways
	applyFullV2HTTPEnrichment(http, payload.Enrichment)
}

func applyPartialV2HTTPPayloadExtraction(cfg *obi.Config, payload schema.PayloadExtraction) {
	if zeroValue(payload) {
		return
	}

	http := &cfg.EBPF.PayloadExtraction.HTTP
	if payload.Enabled != nil {
		applyV2HTTPPayloadExtractorMembership(http, payload.Enabled)
	}
	if payload.SQLPP.EndpointPatterns != nil {
		http.SQLPP.EndpointPatterns = cloneStrings(payload.SQLPP.EndpointPatterns)
	}
	if payload.SQLPP.PreparedStatementsCacheSize != 0 {
		http.SQLPP.PreparedStatementsCacheSize = payload.SQLPP.PreparedStatementsCacheSize
	}
	if payload.OpenAICompatible.Gateways != nil {
		http.GenAI.OpenAICompatible.Gateways = payload.OpenAICompatible.Gateways
	}
	if !zeroValue(payload.Enrichment) {
		applyPartialV2HTTPEnrichment(http, payload.Enrichment)
	}
}

func applyV2HTTPPayloadExtractorMembership(http *obiconfig.HTTPConfig, enabled []string) {
	http.GraphQL.Enabled = false
	http.Elasticsearch.Enabled = false
	http.AWS.Enabled = false
	http.SQLPP.Enabled = false
	http.GenAI.OpenAI.Enabled = false
	http.GenAI.Anthropic.Enabled = false
	http.GenAI.Gemini.Enabled = false
	http.GenAI.Qwen.Enabled = false
	http.GenAI.Bedrock.Enabled = false
	http.GenAI.MCP.Enabled = false
	http.GenAI.Embedding.Enabled = false
	http.GenAI.Rerank.Enabled = false
	http.GenAI.Retrieval.Enabled = false
	http.GenAI.Ollama.Enabled = false
	http.GenAI.Cohere.Enabled = false
	http.GenAI.OpenAICompatible.Enabled = false
	http.JSONRPC.Enabled = false
	http.Enrichment.Enabled = false

	for _, extractor := range enabled {
		switch extractor {
		case payloadExtractorGraphQL:
			http.GraphQL.Enabled = true
		case payloadExtractorElasticsearch:
			http.Elasticsearch.Enabled = true
		case payloadExtractorAWS:
			http.AWS.Enabled = true
		case payloadExtractorSQLPP:
			http.SQLPP.Enabled = true
		case payloadExtractorOpenAI:
			http.GenAI.OpenAI.Enabled = true
		case payloadExtractorAnthropic:
			http.GenAI.Anthropic.Enabled = true
		case payloadExtractorGemini:
			http.GenAI.Gemini.Enabled = true
		case payloadExtractorQwen:
			http.GenAI.Qwen.Enabled = true
		case payloadExtractorBedrock:
			http.GenAI.Bedrock.Enabled = true
		case payloadExtractorMCP:
			http.GenAI.MCP.Enabled = true
		case payloadExtractorEmbedding:
			http.GenAI.Embedding.Enabled = true
		case payloadExtractorRerank:
			http.GenAI.Rerank.Enabled = true
		case payloadExtractorRetrieval:
			http.GenAI.Retrieval.Enabled = true
		case payloadExtractorOllama:
			http.GenAI.Ollama.Enabled = true
		case payloadExtractorCohere:
			http.GenAI.Cohere.Enabled = true
		case payloadExtractorOpenAICompatible:
			http.GenAI.OpenAICompatible.Enabled = true
		case payloadExtractorJSONRPC:
			http.JSONRPC.Enabled = true
		case payloadExtractorEnrichment:
			http.Enrichment.Enabled = true
		}
	}
}

func applyFullV2HTTPEnrichment(http *obiconfig.HTTPConfig, enrichment schema.HTTPEnrichment) {
	http.Enrichment.Policy.DefaultAction.Headers = enrichment.Policy.DefaultAction.Headers
	http.Enrichment.Policy.DefaultAction.Body = enrichment.Policy.DefaultAction.Body
	http.Enrichment.Policy.DefaultObfuscationString = enrichment.Policy.DefaultObfuscationString
	http.Enrichment.Rules = cloneHTTPParsingRules(enrichment.Rules)
}

func applyPartialV2HTTPEnrichment(http *obiconfig.HTTPConfig, enrichment schema.HTTPEnrichment) {
	if !zeroValue(enrichment.Policy.DefaultAction.Headers) {
		http.Enrichment.Policy.DefaultAction.Headers = enrichment.Policy.DefaultAction.Headers
	}
	if !zeroValue(enrichment.Policy.DefaultAction.Body) {
		http.Enrichment.Policy.DefaultAction.Body = enrichment.Policy.DefaultAction.Body
	}
	if enrichment.Policy.DefaultObfuscationString != "" {
		http.Enrichment.Policy.DefaultObfuscationString = enrichment.Policy.DefaultObfuscationString
	}
	if enrichment.Rules != nil {
		http.Enrichment.Rules = cloneHTTPParsingRules(enrichment.Rules)
	}
}

func applyProtocolEnablement(cfg *obi.Config, instrumentation schema.Instrumentation, complete bool) {
	cfg.Traces.Instrumentations = applySignalEnablement(cfg.Traces.Instrumentations, instrumentation, "traces", complete)
	cfg.OTELMetrics.Instrumentations = applySignalEnablement(cfg.OTELMetrics.Instrumentations, instrumentation, "metrics", complete)
	cfg.Prometheus.Instrumentations = applySignalEnablement(cfg.Prometheus.Instrumentations, instrumentation, "metrics", complete)
}

func applySignalEnablement(
	current []instrumentations.Instrumentation,
	instrumentation schema.Instrumentation,
	signal string,
	complete bool,
) []instrumentations.Instrumentation {
	selected := map[instrumentations.Instrumentation]bool{}
	hadWildcard := false
	for _, instr := range current {
		if instr == instrumentations.InstrumentationALL {
			hadWildcard = true
			for _, candidate := range runtimeInstrumentations {
				selected[candidate] = true
			}
			continue
		}
		selected[instr] = true
	}

	for _, mapping := range protocolMappings {
		enablement, explicit := protocolEnablement(instrumentation, mapping.name)
		enabled := signalEnabled(enablement, signal)
		if !complete && !enabled && !explicit {
			continue
		}
		selected[mapping.instr] = enabled
	}

	allEnabled := true
	for _, candidate := range runtimeInstrumentations {
		if !selected[candidate] {
			allEnabled = false
			break
		}
	}
	if hadWildcard && allEnabled {
		return []instrumentations.Instrumentation{instrumentations.InstrumentationALL}
	}

	out := make([]instrumentations.Instrumentation, 0, len(runtimeInstrumentations))
	for _, candidate := range runtimeInstrumentations {
		if selected[candidate] {
			out = append(out, candidate)
		}
	}
	return out
}

func applyV2NetworkCapture(cfg *obi.Config, capture schema.NetworkCapture, complete bool) {
	if zeroValue(capture) && !complete {
		return
	}

	if complete || completeNetworkCapture(capture) {
		applyFullV2NetworkCapture(cfg, capture)
		return
	}

	applyPartialV2NetworkCapture(cfg, capture)
}

func applyFullV2NetworkCapture(cfg *obi.Config, capture schema.NetworkCapture) {
	cfg.NetworkFlows.Enable = capture.Enabled
	cfg.NetworkFlows.Source = string(capture.Source)
	cfg.EBPF.BufferSizes.TCP = capture.BufferSize
	cfg.NetworkFlows.AgentIP = capture.EndpointIdentity.AgentIP
	cfg.NetworkFlows.AgentIPIface = obi.AgentTypeIface(capture.EndpointIdentity.AgentIPInterface)
	cfg.NetworkFlows.AgentIPType = string(capture.EndpointIdentity.AgentIPFamily)
	cfg.NetworkFlows.Interfaces = cloneStrings(capture.Selection.Interfaces.Include)
	cfg.NetworkFlows.ExcludeInterfaces = cloneStrings(capture.Selection.Interfaces.Exclude)
	cfg.NetworkFlows.Protocols = cloneStrings(capture.Selection.Protocols.Include)
	cfg.NetworkFlows.ExcludeProtocols = cloneStrings(capture.Selection.Protocols.Exclude)
	cfg.NetworkFlows.Direction = string(capture.Selection.Direction)
	cfg.NetworkFlows.CIDRs = cloneRuntimeCIDRDefinitions(cfg.NetworkFlows.CIDRs, capture.Selection.CIDRs)
	cfg.Filters.Network = attributeFilterMap(capture.Filters.Traces)
	cfg.NetworkFlows.CacheMaxFlows = capture.FlowLifecycle.MaxTrackedFlows
	cfg.NetworkFlows.CacheActiveTimeout = capture.FlowLifecycle.ActiveTimeout.TimeDuration()
	cfg.NetworkFlows.Deduper = string(capture.FlowLifecycle.Deduplication.Strategy)
	cfg.NetworkFlows.DeduperFCTTL = capture.FlowLifecycle.Deduplication.FirstComeTTL.TimeDuration()
	cfg.NetworkFlows.Sampling = capture.FlowLifecycle.Sampling
	cfg.NetworkFlows.GuessPorts = capture.FlowLifecycle.GuessPorts
	cfg.NetworkFlows.ListenInterfaces = string(capture.InterfaceDiscovery.Mode)
	cfg.NetworkFlows.ListenPollPeriod = capture.InterfaceDiscovery.PollInterval.TimeDuration()
	applyFullV2NetworkEnrichment(cfg, capture.Enrichment)
	cfg.NetworkFlows.Print = capture.Diagnostics.PrintFlows
}

func applyPartialV2NetworkCapture(cfg *obi.Config, capture schema.NetworkCapture) {
	if capture.Enabled {
		cfg.NetworkFlows.Enable = true
	}
	if !zeroValue(capture.Source) {
		cfg.NetworkFlows.Source = string(capture.Source)
	}
	if capture.BufferSize != 0 {
		cfg.EBPF.BufferSizes.TCP = capture.BufferSize
	}
	if capture.EndpointIdentity.AgentIP != "" {
		cfg.NetworkFlows.AgentIP = capture.EndpointIdentity.AgentIP
	}
	if capture.EndpointIdentity.AgentIPInterface != "" {
		cfg.NetworkFlows.AgentIPIface = obi.AgentTypeIface(capture.EndpointIdentity.AgentIPInterface)
	}
	if capture.EndpointIdentity.AgentIPFamily != "" {
		cfg.NetworkFlows.AgentIPType = string(capture.EndpointIdentity.AgentIPFamily)
	}
	if capture.Selection.Interfaces.Include != nil {
		cfg.NetworkFlows.Interfaces = cloneStrings(capture.Selection.Interfaces.Include)
	}
	if capture.Selection.Interfaces.Exclude != nil {
		cfg.NetworkFlows.ExcludeInterfaces = cloneStrings(capture.Selection.Interfaces.Exclude)
	}
	if capture.Selection.Protocols.Include != nil {
		cfg.NetworkFlows.Protocols = cloneStrings(capture.Selection.Protocols.Include)
	}
	if capture.Selection.Protocols.Exclude != nil {
		cfg.NetworkFlows.ExcludeProtocols = cloneStrings(capture.Selection.Protocols.Exclude)
	}
	if capture.Selection.Direction != "" {
		cfg.NetworkFlows.Direction = string(capture.Selection.Direction)
	}
	if capture.Selection.CIDRs != nil {
		cfg.NetworkFlows.CIDRs = cloneRuntimeCIDRDefinitions(cfg.NetworkFlows.CIDRs, capture.Selection.CIDRs)
	}
	if !zeroValue(capture.Filters) {
		cfg.Filters.Network = attributeFilterMap(capture.Filters.Traces)
	}
	if capture.FlowLifecycle.MaxTrackedFlows != 0 {
		cfg.NetworkFlows.CacheMaxFlows = capture.FlowLifecycle.MaxTrackedFlows
	}
	if !zeroValue(capture.FlowLifecycle.ActiveTimeout) {
		cfg.NetworkFlows.CacheActiveTimeout = capture.FlowLifecycle.ActiveTimeout.TimeDuration()
	}
	if capture.FlowLifecycle.Deduplication.Strategy != "" {
		cfg.NetworkFlows.Deduper = string(capture.FlowLifecycle.Deduplication.Strategy)
	}
	if !zeroValue(capture.FlowLifecycle.Deduplication.FirstComeTTL) {
		cfg.NetworkFlows.DeduperFCTTL = capture.FlowLifecycle.Deduplication.FirstComeTTL.TimeDuration()
	}
	if capture.FlowLifecycle.Sampling != 0 {
		cfg.NetworkFlows.Sampling = capture.FlowLifecycle.Sampling
	}
	if capture.FlowLifecycle.GuessPorts != "" {
		cfg.NetworkFlows.GuessPorts = capture.FlowLifecycle.GuessPorts
	}
	if capture.InterfaceDiscovery.Mode != "" {
		cfg.NetworkFlows.ListenInterfaces = string(capture.InterfaceDiscovery.Mode)
	}
	if !zeroValue(capture.InterfaceDiscovery.PollInterval) {
		cfg.NetworkFlows.ListenPollPeriod = capture.InterfaceDiscovery.PollInterval.TimeDuration()
	}
	if !zeroValue(capture.Enrichment) {
		applyPartialV2NetworkEnrichment(cfg, capture.Enrichment)
	}
	if capture.Diagnostics.PrintFlows {
		cfg.NetworkFlows.Print = true
	}
}

func applyFullV2NetworkEnrichment(cfg *obi.Config, enrichment schema.NetworkEnrichment) {
	cfg.NetworkFlows.GeoIP.IPInfo.Path = enrichment.GeoIP.IPInfo.Path
	cfg.NetworkFlows.GeoIP.MaxMindInfo.CountryPath = enrichment.GeoIP.MaxMind.CountryPath
	cfg.NetworkFlows.GeoIP.MaxMindInfo.ASNPath = enrichment.GeoIP.MaxMind.ASNPath
	cfg.NetworkFlows.GeoIP.CacheLen = enrichment.GeoIP.Cache.Size
	cfg.NetworkFlows.GeoIP.CacheTTL = enrichment.GeoIP.Cache.TTL.TimeDuration()
	cfg.NetworkFlows.ReverseDNS.Type = string(enrichment.ReverseDNS.Mode)
	cfg.NetworkFlows.ReverseDNS.CacheLen = enrichment.ReverseDNS.Cache.Size
	cfg.NetworkFlows.ReverseDNS.CacheTTL = enrichment.ReverseDNS.Cache.TTL.TimeDuration()
}

func applyPartialV2NetworkEnrichment(cfg *obi.Config, enrichment schema.NetworkEnrichment) {
	if enrichment.GeoIP.IPInfo.Path != "" {
		cfg.NetworkFlows.GeoIP.IPInfo.Path = enrichment.GeoIP.IPInfo.Path
	}
	if enrichment.GeoIP.MaxMind.CountryPath != "" {
		cfg.NetworkFlows.GeoIP.MaxMindInfo.CountryPath = enrichment.GeoIP.MaxMind.CountryPath
	}
	if enrichment.GeoIP.MaxMind.ASNPath != "" {
		cfg.NetworkFlows.GeoIP.MaxMindInfo.ASNPath = enrichment.GeoIP.MaxMind.ASNPath
	}
	if enrichment.GeoIP.Cache.Size != 0 {
		cfg.NetworkFlows.GeoIP.CacheLen = enrichment.GeoIP.Cache.Size
	}
	if !zeroValue(enrichment.GeoIP.Cache.TTL) {
		cfg.NetworkFlows.GeoIP.CacheTTL = enrichment.GeoIP.Cache.TTL.TimeDuration()
	}
	if enrichment.ReverseDNS.Mode != "" {
		cfg.NetworkFlows.ReverseDNS.Type = string(enrichment.ReverseDNS.Mode)
	}
	if enrichment.ReverseDNS.Cache.Size != 0 {
		cfg.NetworkFlows.ReverseDNS.CacheLen = enrichment.ReverseDNS.Cache.Size
	}
	if !zeroValue(enrichment.ReverseDNS.Cache.TTL) {
		cfg.NetworkFlows.ReverseDNS.CacheTTL = enrichment.ReverseDNS.Cache.TTL.TimeDuration()
	}
}

func applyV2NetworkStats(cfg *obi.Config, stats schema.NetworkStats, complete bool) {
	if zeroValue(stats) && !complete {
		return
	}

	if complete || completeNetworkStats(stats) {
		applyFullV2NetworkStats(cfg, stats)
		return
	}

	applyPartialV2NetworkStats(cfg, stats)
}

func applyFullV2NetworkStats(cfg *obi.Config, stats schema.NetworkStats) {
	cfg.Stats.AgentIP = stats.EndpointIdentity.AgentIP
	cfg.Stats.AgentIPIface = obi.AgentTypeIface(stats.EndpointIdentity.AgentIPInterface)
	cfg.Stats.AgentIPType = string(stats.EndpointIdentity.AgentIPFamily)
	cfg.Stats.CIDRs = cloneRuntimeCIDRDefinitions(cfg.Stats.CIDRs, stats.Selection.CIDRs)
	cfg.Filters.Stats = attributeFilterMap(stats.Filters.Traces)
	applyFullV2StatsEnrichment(cfg, stats.Enrichment)
	cfg.Stats.Print = stats.Diagnostics.PrintStats
}

func applyPartialV2NetworkStats(cfg *obi.Config, stats schema.NetworkStats) {
	if stats.EndpointIdentity.AgentIP != "" {
		cfg.Stats.AgentIP = stats.EndpointIdentity.AgentIP
	}
	if stats.EndpointIdentity.AgentIPInterface != "" {
		cfg.Stats.AgentIPIface = obi.AgentTypeIface(stats.EndpointIdentity.AgentIPInterface)
	}
	if stats.EndpointIdentity.AgentIPFamily != "" {
		cfg.Stats.AgentIPType = string(stats.EndpointIdentity.AgentIPFamily)
	}
	if stats.Selection.CIDRs != nil {
		cfg.Stats.CIDRs = cloneRuntimeCIDRDefinitions(cfg.Stats.CIDRs, stats.Selection.CIDRs)
	}
	if !zeroValue(stats.Filters) {
		cfg.Filters.Stats = attributeFilterMap(stats.Filters.Traces)
	}
	if !zeroValue(stats.Enrichment) {
		applyPartialV2StatsEnrichment(cfg, stats.Enrichment)
	}
	if stats.Diagnostics.PrintStats {
		cfg.Stats.Print = true
	}
}

func applyFullV2StatsEnrichment(cfg *obi.Config, enrichment schema.NetworkEnrichment) {
	cfg.Stats.GeoIP.IPInfo.Path = enrichment.GeoIP.IPInfo.Path
	cfg.Stats.GeoIP.MaxMindInfo.CountryPath = enrichment.GeoIP.MaxMind.CountryPath
	cfg.Stats.GeoIP.MaxMindInfo.ASNPath = enrichment.GeoIP.MaxMind.ASNPath
	cfg.Stats.GeoIP.CacheLen = enrichment.GeoIP.Cache.Size
	cfg.Stats.GeoIP.CacheTTL = enrichment.GeoIP.Cache.TTL.TimeDuration()
	cfg.Stats.ReverseDNS.Type = string(enrichment.ReverseDNS.Mode)
	cfg.Stats.ReverseDNS.CacheLen = enrichment.ReverseDNS.Cache.Size
	cfg.Stats.ReverseDNS.CacheTTL = enrichment.ReverseDNS.Cache.TTL.TimeDuration()
}

func applyPartialV2StatsEnrichment(cfg *obi.Config, enrichment schema.NetworkEnrichment) {
	if enrichment.GeoIP.IPInfo.Path != "" {
		cfg.Stats.GeoIP.IPInfo.Path = enrichment.GeoIP.IPInfo.Path
	}
	if enrichment.GeoIP.MaxMind.CountryPath != "" {
		cfg.Stats.GeoIP.MaxMindInfo.CountryPath = enrichment.GeoIP.MaxMind.CountryPath
	}
	if enrichment.GeoIP.MaxMind.ASNPath != "" {
		cfg.Stats.GeoIP.MaxMindInfo.ASNPath = enrichment.GeoIP.MaxMind.ASNPath
	}
	if enrichment.GeoIP.Cache.Size != 0 {
		cfg.Stats.GeoIP.CacheLen = enrichment.GeoIP.Cache.Size
	}
	if !zeroValue(enrichment.GeoIP.Cache.TTL) {
		cfg.Stats.GeoIP.CacheTTL = enrichment.GeoIP.Cache.TTL.TimeDuration()
	}
	if enrichment.ReverseDNS.Mode != "" {
		cfg.Stats.ReverseDNS.Type = string(enrichment.ReverseDNS.Mode)
	}
	if enrichment.ReverseDNS.Cache.Size != 0 {
		cfg.Stats.ReverseDNS.CacheLen = enrichment.ReverseDNS.Cache.Size
	}
	if !zeroValue(enrichment.ReverseDNS.Cache.TTL) {
		cfg.Stats.ReverseDNS.CacheTTL = enrichment.ReverseDNS.Cache.TTL.TimeDuration()
	}
}

func applyV2Runtimes(cfg *obi.Config, runtimes schema.CaptureRuntimes, complete bool) {
	if zeroValue(runtimes) && !complete {
		return
	}

	if complete || completeRuntimes(runtimes) {
		applyFullV2Runtimes(cfg, runtimes)
		return
	}

	applyPartialV2Runtimes(cfg, runtimes)
}

func applyFullV2Runtimes(cfg *obi.Config, runtimes schema.CaptureRuntimes) {
	cfg.Discovery.SkipGoSpecificTracers = !runtimes.Go.Enabled
	cfg.NodeJS.Enabled = runtimes.NodeJS.Enabled
	cfg.Java.Enabled = runtimes.Java.Enabled
	cfg.Java.Debug = runtimes.Java.Debug.Enabled
	cfg.Java.DebugInstrumentation = runtimes.Java.Debug.BytecodeInstrumentation
	cfg.Java.Timeout = runtimes.Java.AttachTimeout.TimeDuration()
}

func applyPartialV2Runtimes(cfg *obi.Config, runtimes schema.CaptureRuntimes) {
	if runtimes.Go.Enabled {
		cfg.Discovery.SkipGoSpecificTracers = false
	}
	if runtimes.NodeJS.Enabled {
		cfg.NodeJS.Enabled = true
	}
	if runtimes.Java.Enabled {
		cfg.Java.Enabled = true
	}
	if runtimes.Java.Debug.Enabled {
		cfg.Java.Debug = true
	}
	if runtimes.Java.Debug.BytecodeInstrumentation {
		cfg.Java.DebugInstrumentation = true
	}
	if !zeroValue(runtimes.Java.AttachTimeout) {
		cfg.Java.Timeout = runtimes.Java.AttachTimeout.TimeDuration()
	}
}

func applyV2CaptureTelemetry(cfg *obi.Config, telemetry schema.CaptureTelemetry, complete bool) {
	if zeroValue(telemetry) && !complete {
		return
	}

	if complete || completeCaptureTelemetry(telemetry) {
		applyFullV2CaptureTelemetry(cfg, telemetry)
		return
	}

	applyPartialV2CaptureTelemetry(cfg, telemetry)
}

func applyFullV2CaptureTelemetry(cfg *obi.Config, telemetry schema.CaptureTelemetry) {
	cfg.Traces.ReportersCacheLen = telemetry.Traces.ReportersCacheLen
	cfg.OTELMetrics.ReportersCacheLen = telemetry.Metrics.ReportersCacheLen
	cfg.OTELMetrics.TTL = telemetry.Metrics.TTL.TimeDuration()
	if telemetry.Metrics.ConnectionInfoTTL.TimeDuration() > 0 {
		cfg.OTELMetrics.ConnectionInfoTTL = telemetry.Metrics.ConnectionInfoTTL.TimeDuration()
		cfg.Prometheus.ConnectionInfoTTL = telemetry.Metrics.ConnectionInfoTTL.TimeDuration()
	}
}

func applyPartialV2CaptureTelemetry(cfg *obi.Config, telemetry schema.CaptureTelemetry) {
	if telemetry.Traces.ReportersCacheLen != 0 {
		cfg.Traces.ReportersCacheLen = telemetry.Traces.ReportersCacheLen
	}
	if telemetry.Metrics.ReportersCacheLen != 0 {
		cfg.OTELMetrics.ReportersCacheLen = telemetry.Metrics.ReportersCacheLen
	}
	if !zeroValue(telemetry.Metrics.TTL) {
		cfg.OTELMetrics.TTL = telemetry.Metrics.TTL.TimeDuration()
	}
	if !zeroValue(telemetry.Metrics.ConnectionInfoTTL) {
		cfg.OTELMetrics.ConnectionInfoTTL = telemetry.Metrics.ConnectionInfoTTL.TimeDuration()
		cfg.Prometheus.ConnectionInfoTTL = telemetry.Metrics.ConnectionInfoTTL.TimeDuration()
	}
}

func applyV2Standalone(cfg *obi.Config, src *schema.Extension, complete bool) {
	applyV2EnrichAttributes(cfg, src.Enrich, complete)
	applyV2KubernetesEnricher(cfg, src.Enrich, complete)
	applyV2CloudEnricher(cfg, src.Enrich, complete)
	applyV2EnrichServiceName(cfg, src.Enrich)
	applyV2Correlation(cfg, src.Correlation, complete)
	applyV2Daemon(cfg, src.Daemon, complete)
}

func applyV2EnrichAttributes(cfg *obi.Config, enrich *schema.Enrich, complete bool) {
	if enrich == nil || zeroValue(enrich.Attributes) && !complete {
		return
	}

	attrs := enrich.Attributes
	if complete || completeEnrichmentAttributes(attrs) {
		applyFullV2EnrichAttributes(cfg, attrs)
		return
	}

	applyPartialV2EnrichAttributes(cfg, attrs)
}

func applyFullV2EnrichAttributes(cfg *obi.Config, attrs schema.EnrichmentAttributes) {
	cfg.Attributes.Select = cloneAttributeSelection(attrs.Select)
	cfg.Attributes.ExtraGroupAttributes = cloneExtraGroupAttributes(attrs.ExtraGroupAttributes)
	cfg.Attributes.MetadataRetry.Timeout = attrs.MetadataRetry.Timeout.TimeDuration()
	cfg.Attributes.MetadataRetry.StartInterval = attrs.MetadataRetry.StartInterval.TimeDuration()
	cfg.Attributes.MetadataRetry.MaxInterval = attrs.MetadataRetry.MaxInterval.TimeDuration()
}

func applyPartialV2EnrichAttributes(cfg *obi.Config, attrs schema.EnrichmentAttributes) {
	if attrs.Select != nil {
		cfg.Attributes.Select = cloneAttributeSelection(attrs.Select)
	}
	if attrs.ExtraGroupAttributes != nil {
		cfg.Attributes.ExtraGroupAttributes = cloneExtraGroupAttributes(attrs.ExtraGroupAttributes)
	}
	if !zeroValue(attrs.MetadataRetry.Timeout) {
		cfg.Attributes.MetadataRetry.Timeout = attrs.MetadataRetry.Timeout.TimeDuration()
	}
	if !zeroValue(attrs.MetadataRetry.StartInterval) {
		cfg.Attributes.MetadataRetry.StartInterval = attrs.MetadataRetry.StartInterval.TimeDuration()
	}
	if !zeroValue(attrs.MetadataRetry.MaxInterval) {
		cfg.Attributes.MetadataRetry.MaxInterval = attrs.MetadataRetry.MaxInterval.TimeDuration()
	}
}

func applyV2KubernetesEnricher(cfg *obi.Config, enrich *schema.Enrich, complete bool) {
	if enrich == nil || zeroValue(enrich.Enrichers.Kubernetes) && !complete {
		return
	}

	kubernetes := enrich.Enrichers.Kubernetes
	if complete || completeKubernetesEnricher(kubernetes) {
		applyFullV2KubernetesEnricher(cfg, kubernetes)
		return
	}

	applyPartialV2KubernetesEnricher(cfg, kubernetes)
}

func applyFullV2KubernetesEnricher(cfg *obi.Config, kubernetes schema.KubernetesEnricher) {
	cfg.Attributes.Kubernetes.Enable = runtimeKubernetesMode(kubernetes.Mode)
	cfg.Attributes.Kubernetes.ClusterName = kubernetes.ClusterName
	cfg.Attributes.Kubernetes.KubeconfigPath = kubernetes.Auth.KubeconfigPath
	cfg.Attributes.Kubernetes.InformersSyncTimeout = kubernetes.Informers.InitialSyncTimeout.TimeDuration()
	cfg.Attributes.Kubernetes.ReconnectInitialInterval = kubernetes.Informers.ReconnectInitialInterval.TimeDuration()
	cfg.Attributes.Kubernetes.InformersResyncPeriod = kubernetes.Informers.ResyncPeriod.TimeDuration()
	cfg.Attributes.Kubernetes.DropExternal = kubernetes.DropExternal
	cfg.Attributes.Kubernetes.DisableInformers = cloneStrings(kubernetes.Informers.Disabled)
	cfg.Attributes.Kubernetes.MetaCacheAddress = kubernetes.MetadataCache.Address
	cfg.Attributes.Kubernetes.MetaRestrictLocalNode = kubernetes.MetadataCache.RestrictLocalNode
	cfg.Attributes.Kubernetes.MetaSourceLabels.ServiceName = kubernetes.MetadataCache.SourceLabels.ServiceName
	cfg.Attributes.Kubernetes.MetaSourceLabels.ServiceNamespace = kubernetes.MetadataCache.SourceLabels.ServiceNamespace
	cfg.Attributes.Kubernetes.ResourceLabels = cloneStringMap(kubernetes.ResourceLabels)
	cfg.Attributes.Kubernetes.ServiceNameTemplate = kubernetes.ServiceNameTemplate
}

func applyPartialV2KubernetesEnricher(cfg *obi.Config, kubernetes schema.KubernetesEnricher) {
	if kubernetes.Mode != "" {
		cfg.Attributes.Kubernetes.Enable = runtimeKubernetesMode(kubernetes.Mode)
	}
	if kubernetes.ClusterName != "" {
		cfg.Attributes.Kubernetes.ClusterName = kubernetes.ClusterName
	}
	if kubernetes.ServiceNameTemplate != "" {
		cfg.Attributes.Kubernetes.ServiceNameTemplate = kubernetes.ServiceNameTemplate
	}
	if kubernetes.Auth.KubeconfigPath != "" {
		cfg.Attributes.Kubernetes.KubeconfigPath = kubernetes.Auth.KubeconfigPath
	}
	if !zeroValue(kubernetes.Informers.InitialSyncTimeout) {
		cfg.Attributes.Kubernetes.InformersSyncTimeout = kubernetes.Informers.InitialSyncTimeout.TimeDuration()
	}
	if !zeroValue(kubernetes.Informers.ReconnectInitialInterval) {
		cfg.Attributes.Kubernetes.ReconnectInitialInterval = kubernetes.Informers.ReconnectInitialInterval.TimeDuration()
	}
	if !zeroValue(kubernetes.Informers.ResyncPeriod) {
		cfg.Attributes.Kubernetes.InformersResyncPeriod = kubernetes.Informers.ResyncPeriod.TimeDuration()
	}
	if kubernetes.Informers.Disabled != nil {
		cfg.Attributes.Kubernetes.DisableInformers = cloneStrings(kubernetes.Informers.Disabled)
	}
	if kubernetes.DropExternal {
		cfg.Attributes.Kubernetes.DropExternal = kubernetes.DropExternal
	}
	if kubernetes.ResourceLabels != nil {
		cfg.Attributes.Kubernetes.ResourceLabels = cloneStringMap(kubernetes.ResourceLabels)
	}
	if kubernetes.MetadataCache.Address != "" {
		cfg.Attributes.Kubernetes.MetaCacheAddress = kubernetes.MetadataCache.Address
	}
	if kubernetes.MetadataCache.RestrictLocalNode {
		cfg.Attributes.Kubernetes.MetaRestrictLocalNode = kubernetes.MetadataCache.RestrictLocalNode
	}
	if kubernetes.MetadataCache.SourceLabels.ServiceName != "" {
		cfg.Attributes.Kubernetes.MetaSourceLabels.ServiceName = kubernetes.MetadataCache.SourceLabels.ServiceName
	}
	if kubernetes.MetadataCache.SourceLabels.ServiceNamespace != "" {
		cfg.Attributes.Kubernetes.MetaSourceLabels.ServiceNamespace = kubernetes.MetadataCache.SourceLabels.ServiceNamespace
	}
}

func applyV2CloudEnricher(cfg *obi.Config, enrich *schema.Enrich, complete bool) {
	if enrich == nil || zeroValue(enrich.Enrichers.Cloud) && !complete {
		return
	}

	cloud := enrich.Enrichers.Cloud
	if complete || completeCloudEnricher(cloud) {
		applyFullV2CloudEnricher(cfg, cloud)
		return
	}

	applyPartialV2CloudEnricher(cfg, cloud)
}

func applyFullV2CloudEnricher(cfg *obi.Config, cloud schema.CloudEnricher) {
	cfg.CloudMetadata.ClusterName = cloud.ClusterName
	cfg.CloudMetadata.Region = cloud.Region
	cfg.CloudMetadata.RefreshInterval = cloud.RefreshInterval.TimeDuration()
	cfg.CloudMetadata.Route53.RefreshInterval = cloud.Route53.RefreshInterval.TimeDuration()
	cfg.CloudMetadata.Route53.HostedZoneIDs = cloneStrings(cloud.Route53.HostedZoneIDs)
}

func applyPartialV2CloudEnricher(cfg *obi.Config, cloud schema.CloudEnricher) {
	if cloud.ClusterName != "" {
		cfg.CloudMetadata.ClusterName = cloud.ClusterName
	}
	if cloud.Region != "" {
		cfg.CloudMetadata.Region = cloud.Region
	}
	if !zeroValue(cloud.RefreshInterval) {
		cfg.CloudMetadata.RefreshInterval = cloud.RefreshInterval.TimeDuration()
	}
	if !zeroValue(cloud.Route53.RefreshInterval) {
		cfg.CloudMetadata.Route53.RefreshInterval = cloud.Route53.RefreshInterval.TimeDuration()
	}
	if cloud.Route53.HostedZoneIDs != nil {
		cfg.CloudMetadata.Route53.HostedZoneIDs = cloneStrings(cloud.Route53.HostedZoneIDs)
	}
}

func applyV2EnrichServiceName(cfg *obi.Config, enrich *schema.Enrich) {
	if enrich == nil || zeroValue(enrich.ServiceName) {
		return
	}

	serviceName := enrich.ServiceName
	if cfg.NameResolver == nil {
		cfg.NameResolver = &transform.NameResolverConfig{}
	}

	cfg.NameResolver.Sources = cloneSources(serviceName.Sources)
	if serviceName.GCE != nil {
		cfg.NameResolver.GCE = *serviceName.GCE
	}
	cfg.NameResolver.Azure = transform.AzureNameResolverConfig{
		SubscriptionID: serviceName.Azure.SubscriptionID,
		ResourceGroup:  serviceName.Azure.ResourceGroup,
	}
	cfg.NameResolver.CacheLen = serviceName.Cache.Size
	cfg.NameResolver.CacheTTL = serviceName.Cache.TTL.TimeDuration()
	cfg.Attributes.RenameUnresolvedHosts = serviceName.UnresolvedHosts.Names.Default
	cfg.Attributes.RenameUnresolvedHostsOutgoing = serviceName.UnresolvedHosts.Names.Outgoing
	cfg.Attributes.RenameUnresolvedHostsIncoming = serviceName.UnresolvedHosts.Names.Incoming
}

func applyV2Correlation(cfg *obi.Config, correlation *schema.Correlation, complete bool) {
	if correlation == nil || zeroValue(correlation.LogTraceAnnotation) && !complete {
		return
	}

	if !complete && !completeLogTraceAnnotation(correlation.LogTraceAnnotation) {
		applyPartialV2Correlation(cfg, correlation.LogTraceAnnotation)
		return
	}

	applyFullV2Correlation(cfg, correlation.LogTraceAnnotation)
}

func applyFullV2Correlation(cfg *obi.Config, logTrace schema.LogTraceAnnotation) {
	cfg.EBPF.LogEnricher.Services = logEnricherServicesFromV2(logTrace)
	cfg.EBPF.LogEnricher.FieldNames.TraceID = *logTrace.FieldNames.TraceID
	cfg.EBPF.LogEnricher.FieldNames.SpanID = *logTrace.FieldNames.SpanID
	cfg.EBPF.LogEnricher.PlainText.Enabled = *logTrace.PlainText.Enabled
	cfg.EBPF.LogEnricher.PlainText.Placement = *logTrace.PlainText.Placement
	cfg.EBPF.LogEnricher.PlainText.Multiline = *logTrace.PlainText.Multiline
	cfg.EBPF.LogEnricher.CacheTTL = logTrace.Cache.TTL.TimeDuration()
	cfg.EBPF.LogEnricher.CacheSize = logTrace.Cache.Size
	cfg.EBPF.LogEnricher.AsyncWriterWorkers = logTrace.AsyncWriter.Workers
	cfg.EBPF.LogEnricher.AsyncWriterChannelLen = logTrace.AsyncWriter.ChannelLen
}

func applyPartialV2Correlation(cfg *obi.Config, logTrace schema.LogTraceAnnotation) {
	if logTrace.Enabled {
		cfg.EBPF.LogEnricher.Services = logEnricherServicesFromV2(logTrace)
	}
	if logTrace.FieldNames.TraceID != nil {
		cfg.EBPF.LogEnricher.FieldNames.TraceID = *logTrace.FieldNames.TraceID
	}
	if logTrace.FieldNames.SpanID != nil {
		cfg.EBPF.LogEnricher.FieldNames.SpanID = *logTrace.FieldNames.SpanID
	}
	if logTrace.PlainText.Enabled != nil {
		cfg.EBPF.LogEnricher.PlainText.Enabled = *logTrace.PlainText.Enabled
	}
	if logTrace.PlainText.Placement != nil {
		cfg.EBPF.LogEnricher.PlainText.Placement = *logTrace.PlainText.Placement
	}
	if logTrace.PlainText.Multiline != nil {
		cfg.EBPF.LogEnricher.PlainText.Multiline = *logTrace.PlainText.Multiline
	}
	if !zeroValue(logTrace.Cache.TTL) {
		cfg.EBPF.LogEnricher.CacheTTL = logTrace.Cache.TTL.TimeDuration()
	}
	if logTrace.Cache.Size != 0 {
		cfg.EBPF.LogEnricher.CacheSize = logTrace.Cache.Size
	}
	if logTrace.AsyncWriter.Workers != 0 {
		cfg.EBPF.LogEnricher.AsyncWriterWorkers = logTrace.AsyncWriter.Workers
	}
	if logTrace.AsyncWriter.ChannelLen != 0 {
		cfg.EBPF.LogEnricher.AsyncWriterChannelLen = logTrace.AsyncWriter.ChannelLen
	}
}

// Each match clause becomes one log enricher selector, kept as a subset of the
// instrumented workloads by the discovery matcher
func logEnricherServicesFromV2(logTrace schema.LogTraceAnnotation) []obiconfig.LogEnricherServiceConfig {
	if !logTrace.Enabled {
		return nil
	}

	svcs := make([]obiconfig.LogEnricherServiceConfig, 0, len(logTrace.Match))
	for _, match := range logTrace.Match {
		svcs = append(svcs, obiconfig.LogEnricherServiceConfig{
			Service: services.GlobDefinitionCriteria{globSelectorFromMatch(match)},
		})
	}
	return svcs
}

func completeLogTraceAnnotation(logTrace schema.LogTraceAnnotation) bool {
	return logTrace.FieldNames.TraceID != nil &&
		logTrace.FieldNames.SpanID != nil &&
		logTrace.PlainText.Enabled != nil &&
		logTrace.PlainText.Placement != nil &&
		logTrace.PlainText.Multiline != nil &&
		!zeroValue(logTrace.Cache.TTL) &&
		logTrace.Cache.Size != 0 &&
		logTrace.AsyncWriter.Workers != 0 &&
		logTrace.AsyncWriter.ChannelLen != 0
}

func applyV2Daemon(cfg *obi.Config, daemon *schema.Daemon, complete bool) {
	if daemon == nil || zeroValue(*daemon) && !complete {
		return
	}

	if !complete && !completeDaemon(*daemon) {
		applyPartialV2Daemon(cfg, *daemon)
		return
	}

	applyFullV2Daemon(cfg, *daemon)
}

func applyFullV2Daemon(cfg *obi.Config, daemon schema.Daemon) {
	if !zeroValue(daemon.Logging) {
		if daemon.Logging.Format != "" {
			cfg.LogFormat = obi.LogFormat(daemon.Logging.Format)
		}
		if daemon.Logging.ConfigFormat != "" {
			cfg.LogConfig = obi.LogConfigOption(daemon.Logging.ConfigFormat)
		}
		if daemon.Logging.DebugTraceOutput != "" {
			cfg.TracePrinter = daemon.Logging.DebugTraceOutput
		}
	}
	if cfg.TracePrinter == "" {
		cfg.TracePrinter = debug.TracePrinterDisabled
	}

	cfg.ProfilePort = daemon.Profiling.Port
	cfg.ShutdownTimeout = daemon.Shutdown.Timeout.TimeDuration()
	cfg.InternalMetrics.Exporter = daemon.InternalMetrics.Exporter
	cfg.InternalMetrics.Prometheus.Port = daemon.InternalMetrics.Prometheus.Port
	cfg.InternalMetrics.Prometheus.Path = daemon.InternalMetrics.Prometheus.Path
	cfg.InternalMetrics.BpfMetricScrapeInterval = daemon.InternalMetrics.BPF.ScrapeInterval.TimeDuration()

	prometheus := daemon.Telemetry.Metrics.Prometheus
	cfg.Prometheus.AllowServiceGraphSelfReferences = prometheus.AllowServiceGraphSelfReferences
	cfg.Prometheus.SpanMetricsServiceCacheSize = prometheus.SpanMetricsServiceCacheSize
	cfg.Prometheus.ExtraResourceLabels = cloneStrings(prometheus.ExtraResourceAttributes)
	cfg.Prometheus.ExtraSpanResourceLabels = cloneStrings(prometheus.ExtraSpanResourceAttributes)
}

func applyPartialV2Daemon(cfg *obi.Config, daemon schema.Daemon) {
	if !zeroValue(daemon.Logging) {
		if daemon.Logging.Format != "" {
			cfg.LogFormat = obi.LogFormat(daemon.Logging.Format)
		}
		if daemon.Logging.ConfigFormat != "" {
			cfg.LogConfig = obi.LogConfigOption(daemon.Logging.ConfigFormat)
		}
		if daemon.Logging.DebugTraceOutput != "" {
			cfg.TracePrinter = daemon.Logging.DebugTraceOutput
		}
	}
	if daemon.Profiling.Port != 0 {
		cfg.ProfilePort = daemon.Profiling.Port
	}
	if !zeroValue(daemon.Shutdown.Timeout) {
		cfg.ShutdownTimeout = daemon.Shutdown.Timeout.TimeDuration()
	}
	if !zeroValue(daemon.InternalMetrics) {
		if daemon.InternalMetrics.Exporter != "" {
			cfg.InternalMetrics.Exporter = daemon.InternalMetrics.Exporter
		}
		if daemon.InternalMetrics.Prometheus.Port != 0 {
			cfg.InternalMetrics.Prometheus.Port = daemon.InternalMetrics.Prometheus.Port
		}
		if daemon.InternalMetrics.Prometheus.Path != "" {
			cfg.InternalMetrics.Prometheus.Path = daemon.InternalMetrics.Prometheus.Path
		}
		if !zeroValue(daemon.InternalMetrics.BPF.ScrapeInterval) {
			cfg.InternalMetrics.BpfMetricScrapeInterval = daemon.InternalMetrics.BPF.ScrapeInterval.TimeDuration()
		}
	}

	prometheus := daemon.Telemetry.Metrics.Prometheus
	if prometheus.AllowServiceGraphSelfReferences {
		cfg.Prometheus.AllowServiceGraphSelfReferences = true
	}
	if prometheus.SpanMetricsServiceCacheSize != 0 {
		cfg.Prometheus.SpanMetricsServiceCacheSize = prometheus.SpanMetricsServiceCacheSize
	}
	if prometheus.ExtraResourceAttributes != nil {
		cfg.Prometheus.ExtraResourceLabels = cloneStrings(prometheus.ExtraResourceAttributes)
	}
	if prometheus.ExtraSpanResourceAttributes != nil {
		cfg.Prometheus.ExtraSpanResourceLabels = cloneStrings(prometheus.ExtraSpanResourceAttributes)
	}
}

func completeDaemon(daemon schema.Daemon) bool {
	return completeDaemonLogging(daemon.Logging) &&
		!zeroValue(daemon.Shutdown.Timeout) &&
		completeInternalMetrics(daemon.InternalMetrics) &&
		completeDaemonTelemetry(daemon.Telemetry)
}

func completeDaemonLogging(logging schema.Logging) bool {
	return logging.Format != "" &&
		logging.DebugTraceOutput != ""
}

func completeInternalMetrics(metrics schema.InternalMetrics) bool {
	return metrics.Exporter != "" &&
		metrics.Prometheus.Path != "" &&
		!zeroValue(metrics.BPF.ScrapeInterval)
}

func completeDaemonTelemetry(telemetry schema.DaemonTelemetry) bool {
	return telemetry.Metrics.Prometheus.SpanMetricsServiceCacheSize != 0
}

func applyV2MetricsEnablement(cfg *obi.Config, src *schema.Extension, complete bool) error {
	if features := src.Capture.Metrics.Features; features != nil {
		mask, err := export.LoadV2Features(features)
		if err != nil {
			return fmt.Errorf("capture.metrics.features: %w", err)
		}
		cfg.Metrics.Features = mask
		return nil
	}

	appMetricsEnabled, appConfigured := appMetricsEnablement(
		src.Capture.Instrumentation,
		complete || completeInstrumentation(src.Capture.Instrumentation),
	)
	networkConfigured := complete || !zeroValue(src.Capture.Network.Capture)
	networkMetricsEnabled := src.Capture.Network.Capture.Enabled
	statsFeatures, statsConfigured := statsMetricsEnablement(src.Capture.Network.Stats)
	statsConfigured = complete || statsConfigured
	if appConfigured {
		cfg.Metrics.Features &^= v2AppMetricsFeatureMask
		if appMetricsEnabled {
			cfg.Metrics.Features |= export.FeatureApplicationRED

			// the size histograms ride on the HTTP metric pipeline, so they follow the
			// HTTP metrics switch rather than the aggregate application one
			http := src.Capture.Instrumentation.HTTP.Enabled
			if http.Metrics && http.BodySizeMetrics {
				cfg.Metrics.Features |= export.FeatureApplicationSizes
			}
		}
	}
	if networkConfigured {
		cfg.Metrics.Features &^= v2NetworkMetricsFeatureMask
		if networkMetricsEnabled {
			cfg.Metrics.Features |= export.FeatureNetwork
		}
	}
	if statsConfigured {
		cfg.Metrics.Features &^= v2StatsMetricsFeatureMask
		cfg.Metrics.Features |= statsFeatures
	}
	return nil
}

func appMetricsEnablement(instrumentation schema.Instrumentation, complete bool) (bool, bool) {
	if zeroValue(instrumentation) {
		return false, false
	}

	configured := complete
	enabled := false
	for _, mapping := range protocolMappings {
		enablement, _ := protocolEnablement(instrumentation, mapping.name)
		metricsEnabled := signalEnabled(enablement, "metrics")
		if !complete && !metricsEnabled {
			continue
		}
		configured = true
		if metricsEnabled && mapping.appMetrics {
			enabled = true
		}
	}
	return enabled, configured
}

func completeInstrumentationWithoutAerospike(instrumentation schema.Instrumentation) bool {
	return !zeroValue(instrumentation.HTTP) &&
		!zeroValue(instrumentation.GRPC) &&
		!zeroValue(instrumentation.SQL) &&
		!zeroValue(instrumentation.Redis) &&
		!zeroValue(instrumentation.Kafka) &&
		!zeroValue(instrumentation.Mongo) &&
		!zeroValue(instrumentation.Couchbase) &&
		!zeroValue(instrumentation.DNS) &&
		!zeroValue(instrumentation.GPU)
}

func completeInstrumentation(instrumentation schema.Instrumentation) bool {
	return completeInstrumentationWithoutAerospike(instrumentation) && instrumentation.Aerospike != nil
}

func completePolicy(policy schema.CapturePolicy) bool {
	return !zeroValue(policy.PollInterval) &&
		!zeroValue(policy.MinProcessAge)
}

func completeLimits(limits schema.CaptureLimits) bool {
	return limits.MetricSpanNames != 0 &&
		limits.NetworkPackets != 0
}

func completeChannels(channels schema.CaptureChannels) bool {
	return channels.BufferLen != 0 &&
		!zeroValue(channels.SendTimeout)
}

func completeEngine(engine schema.CaptureEngine) bool {
	return !zeroValue(engine.Batching) &&
		!zeroValue(engine.Traffic.ControlBackend) &&
		!zeroValue(engine.Transactions.MaxDuration) &&
		engine.BPFFileSystem.Path != ""
}

func completeNetworkCapture(capture schema.NetworkCapture) bool {
	return !zeroValue(capture.Source) &&
		!zeroValue(capture.EndpointIdentity) &&
		!zeroValue(capture.Selection) &&
		capture.Selection.CIDRs != nil &&
		capture.Filters.Traces != nil &&
		capture.Filters.Metrics != nil &&
		!zeroValue(capture.FlowLifecycle) &&
		!zeroValue(capture.InterfaceDiscovery) &&
		!zeroValue(capture.Enrichment)
}

func completeNetworkStats(stats schema.NetworkStats) bool {
	return stats.Features != nil &&
		!zeroValue(stats.EndpointIdentity) &&
		stats.Selection.CIDRs != nil &&
		stats.Filters.Traces != nil &&
		stats.Filters.Metrics != nil &&
		!zeroValue(stats.Enrichment)
}

func completeRuntimes(runtimes schema.CaptureRuntimes) bool {
	return !zeroValue(runtimes.Java.AttachTimeout) &&
		(runtimes.Go.Enabled ||
			runtimes.NodeJS.Enabled ||
			runtimes.Java.Enabled ||
			!zeroValue(runtimes.Java.Debug))
}

func completeCaptureTelemetry(telemetry schema.CaptureTelemetry) bool {
	return !zeroValue(telemetry.Traces) &&
		!zeroValue(telemetry.Metrics)
}

func completeEnrichmentAttributes(attrs schema.EnrichmentAttributes) bool {
	return !zeroValue(attrs.MetadataRetry.StartInterval) &&
		!zeroValue(attrs.MetadataRetry.MaxInterval)
}

func completeCloudEnricher(cloud schema.CloudEnricher) bool {
	return !zeroValue(cloud.RefreshInterval) && !zeroValue(cloud.Route53.RefreshInterval) && cloud.Route53.HostedZoneIDs != nil
}

func completeKubernetesEnricher(kubernetes schema.KubernetesEnricher) bool {
	return kubernetes.Mode != "" &&
		!zeroValue(kubernetes.Informers.InitialSyncTimeout) &&
		!zeroValue(kubernetes.Informers.ReconnectInitialInterval) &&
		kubernetes.ResourceLabels != nil
}

func cloneStringMap(values map[string][]string) map[string][]string {
	if values == nil {
		return nil
	}
	out := make(map[string][]string, len(values))
	for key, value := range values {
		out[key] = cloneStrings(value)
	}
	return out
}

func cloneAttributeSelection(values attributes.Selection) attributes.Selection {
	if values == nil {
		return nil
	}
	out := make(attributes.Selection, len(values))
	for section, inclusionLists := range values {
		out[section] = attributes.InclusionLists{
			Include: cloneStrings(inclusionLists.Include),
			Exclude: cloneStrings(inclusionLists.Exclude),
		}
	}
	return out
}

func cloneExtraGroupAttributes(values schema.ExtraGroupAttributes) obi.ExtraGroupAttributesMap {
	if values == nil {
		return nil
	}
	out := make(obi.ExtraGroupAttributesMap, len(values))
	for group, names := range values {
		out[group] = append(out[group], names...)
	}
	return out
}

func protocolEnablement(instrumentation schema.Instrumentation, name protocolName) (schema.ProtocolEnablement, bool) {
	switch name {
	case protocolHTTP:
		return instrumentation.HTTP.Enabled.ProtocolEnablement, false
	case protocolGRPC:
		return instrumentation.GRPC.Enabled, false
	case protocolSQL:
		return instrumentation.SQL.Enabled, false
	case protocolRedis:
		return instrumentation.Redis.Enabled, false
	case protocolKafka:
		return instrumentation.Kafka.Enabled, false
	case protocolMongo:
		return instrumentation.Mongo.Enabled, false
	case protocolCouchbase:
		return instrumentation.Couchbase.Enabled, false
	case protocolDNS:
		return instrumentation.DNS.Enabled, false
	case protocolGPU:
		return instrumentation.GPU.Enabled, false
	case protocolAerospike:
		if instrumentation.Aerospike != nil {
			return instrumentation.Aerospike.Enabled, true
		}
		return schema.ProtocolEnablement{}, false
	default:
		return schema.ProtocolEnablement{}, false
	}
}

func protocolFilters(instrumentation schema.Instrumentation, name protocolName) schema.SignalFilters {
	switch name {
	case protocolHTTP:
		return instrumentation.HTTP.Filters
	case protocolGRPC:
		return instrumentation.GRPC.Filters
	case protocolSQL:
		return instrumentation.SQL.Filters
	case protocolRedis:
		return instrumentation.Redis.Filters
	case protocolKafka:
		return instrumentation.Kafka.Filters
	case protocolMongo:
		return instrumentation.Mongo.Filters
	case protocolCouchbase:
		return instrumentation.Couchbase.Filters
	case protocolDNS:
		return instrumentation.DNS.Filters
	case protocolGPU:
		return instrumentation.GPU.Filters
	case protocolAerospike:
		if instrumentation.Aerospike != nil {
			return instrumentation.Aerospike.Filters
		}
		return schema.SignalFilters{}
	default:
		return schema.SignalFilters{}
	}
}

func statsMetricsEnablement(stats schema.NetworkStats) (export.Features, bool) {
	if stats.Features != nil {
		return statsFeatureMask(stats.Features), true
	}
	if stats.Enabled {
		return export.FeatureStats, true
	}
	return 0, false
}

func statsFeatureMask(features []string) export.Features {
	out := export.Features(0)
	for _, feature := range features {
		switch feature {
		case statsFeatureTCPRtt:
			out |= export.FeatureStatsTCPRtt
		case statsFeatureTCPFailedConnections:
			out |= export.FeatureStatsTCPFailedConnections
		case statsFeatureTCPSuccessfulConnections:
			out |= export.FeatureStatsTCPSuccessfulConnections
		case statsFeatureTCPRetransmits:
			out |= export.FeatureStatsTCPRetransmits
		case statsFeatureTCPIo:
			out |= export.FeatureStatsTCPIo
		}
	}
	return out
}

func signalEnabled(enablement schema.ProtocolEnablement, signal string) bool {
	switch signal {
	case "traces":
		return enablement.Traces
	case "metrics":
		return enablement.Metrics
	default:
		return false
	}
}

func zeroValue(value any) bool {
	if value == nil {
		return true
	}
	return reflect.ValueOf(value).IsZero()
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string(nil), values...)
}

func cloneStringsPointer(values *[]string) *[]string {
	if values == nil {
		return nil
	}
	cloned := cloneStrings(*values)
	return &cloned
}

func cloneValue[T any](value *T) *T {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneRouteHarvesterLanguages(values []services.RouteHarvesterLanguage) []services.RouteHarvesterLanguage {
	if values == nil {
		return nil
	}
	return append([]services.RouteHarvesterLanguage(nil), values...)
}

func cloneHTTPParsingRules(values []obiconfig.HTTPParsingRule) []obiconfig.HTTPParsingRule {
	if values == nil {
		return nil
	}
	return append([]obiconfig.HTTPParsingRule(nil), values...)
}

type runtimeCIDRDefinition interface {
	~struct {
		CIDR    string `yaml:"cidr" json:"cidr"`
		Name    string `yaml:"name" json:"name"`
		Mapping bool   `yaml:"-" json:"-"`
	}
}

type runtimeCIDRDefinitionValue struct {
	CIDR    string `yaml:"cidr" json:"cidr"`
	Name    string `yaml:"name" json:"name"`
	Mapping bool   `yaml:"-" json:"-"`
}

func cloneRuntimeCIDRDefinitions[T runtimeCIDRDefinition](_ []T, definitions schema.CIDRDefinitions) []T {
	if definitions == nil {
		return nil
	}
	out := make([]T, 0, len(definitions))
	for _, definition := range definitions {
		out = append(out, T(runtimeCIDRDefinitionValue{
			CIDR: definition.CIDR,
			Name: definition.Name,
		}))
	}
	return out
}

func attributeFilterMap(in schema.AttributeFilters) filter.AttributeFamilyConfig {
	if len(in) == 0 {
		return nil
	}
	out := make(filter.AttributeFamilyConfig, len(in))
	for key, def := range in {
		out[key] = filter.MatchDefinition{
			Match:         def.Match,
			NotMatch:      def.NotMatch,
			Equals:        def.Equals,
			NotEquals:     def.NotEquals,
			GreaterEquals: def.GreaterEquals,
			GreaterThan:   def.GreaterThan,
			LessEquals:    def.LessEquals,
			LessThan:      def.LessThan,
		}
	}
	return out
}

func cloneSources(values []transform.Source) []transform.Source {
	if values == nil {
		return nil
	}
	return append([]transform.Source(nil), values...)
}

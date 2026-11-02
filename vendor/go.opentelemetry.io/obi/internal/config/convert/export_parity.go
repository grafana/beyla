// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert // import "go.opentelemetry.io/obi/internal/config/convert"

import (
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/gobwas/glob/syntax"
	"github.com/gobwas/glob/syntax/ast"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/obi"
)

func httpRoutes(cfg *obi.Config) schema.HTTPRoutes {
	out := schema.HTTPRoutes{
		Discovery: schema.HTTPRouteDiscovery{
			Timeout:           schema.Duration(cfg.Discovery.RouteHarvesterTimeout),
			DisabledLanguages: cfg.Discovery.DisabledRouteHarvesters,
			Java: schema.HTTPRouteJavaDiscovery{
				Delay: schema.Duration(cfg.Discovery.RouteHarvestConfig.JavaHarvestDelay),
			},
		},
	}
	if cfg.Routes == nil || cfg.Routes.DirectionalRuleOnly {
		return out
	}

	policies := cfg.Routes.DirectionalPolicies()
	if cfg.Routes.HasIncomingPolicy() {
		out.Incoming = httpRoutePolicy(policies.Incoming)
	}
	if cfg.Routes.HasOutgoingPolicy() {
		out.Outgoing = httpRoutePolicy(policies.Outgoing)
	}
	return out
}

func httpRoutePolicy(policy services.RoutePolicy) *schema.HTTPRoutePolicy {
	unmatched := policy.Unmatch
	if unmatched == "" {
		unmatched = services.UnmatchWildcard
	}
	patterns := cloneStrings(policy.Patterns)
	ignoredPatterns := cloneStrings(policy.IgnorePatterns)
	ignoreMode := policy.IgnoredEvents
	if ignoreMode == "" {
		ignoreMode = services.IgnoreDefault
	}
	wildcardChar := policy.WildcardChar
	if wildcardChar == "" {
		wildcardChar = "*"
	}
	maxPathSegmentCardinality := policy.MaxPathSegmentCardinality
	return &schema.HTTPRoutePolicy{
		Unmatched:                 &unmatched,
		Patterns:                  &patterns,
		IgnoredPatterns:           &ignoredPatterns,
		IgnoreMode:                &ignoreMode,
		WildcardChar:              &wildcardChar,
		MaxPathSegmentCardinality: &maxPathSegmentCardinality,
	}
}

const (
	payloadExtractorGraphQL          = "graphql"
	payloadExtractorElasticsearch    = "elasticsearch"
	payloadExtractorAWS              = "aws"
	payloadExtractorSQLPP            = "sqlpp"
	payloadExtractorOpenAI           = "openai"
	payloadExtractorAnthropic        = "anthropic"
	payloadExtractorGemini           = "gemini"
	payloadExtractorQwen             = "qwen"
	payloadExtractorBedrock          = "bedrock"
	payloadExtractorMCP              = "mcp"
	payloadExtractorEmbedding        = "embedding"
	payloadExtractorRerank           = "rerank"
	payloadExtractorRetrieval        = "retrieval"
	payloadExtractorOllama           = "ollama"
	payloadExtractorCohere           = "cohere"
	payloadExtractorOpenAICompatible = "openai_compatible"
	payloadExtractorJSONRPC          = "jsonrpc"
	payloadExtractorEnrichment       = "enrichment"
)

func payloadExtraction(cfg *obi.Config) schema.PayloadExtraction {
	http := cfg.EBPF.PayloadExtraction.HTTP
	enabled := []string{}
	if http.GraphQL.Enabled {
		enabled = append(enabled, payloadExtractorGraphQL)
	}
	if http.Elasticsearch.Enabled {
		enabled = append(enabled, payloadExtractorElasticsearch)
	}
	if http.AWS.Enabled {
		enabled = append(enabled, payloadExtractorAWS)
	}
	if http.SQLPP.Enabled {
		enabled = append(enabled, payloadExtractorSQLPP)
	}
	if http.GenAI.OpenAI.Enabled {
		enabled = append(enabled, payloadExtractorOpenAI)
	}
	if http.GenAI.Anthropic.Enabled {
		enabled = append(enabled, payloadExtractorAnthropic)
	}
	if http.GenAI.Gemini.Enabled {
		enabled = append(enabled, payloadExtractorGemini)
	}
	if http.GenAI.Qwen.Enabled {
		enabled = append(enabled, payloadExtractorQwen)
	}
	if http.GenAI.Bedrock.Enabled {
		enabled = append(enabled, payloadExtractorBedrock)
	}
	if http.GenAI.MCP.Enabled {
		enabled = append(enabled, payloadExtractorMCP)
	}
	if http.GenAI.Embedding.Enabled {
		enabled = append(enabled, payloadExtractorEmbedding)
	}
	if http.GenAI.Rerank.Enabled {
		enabled = append(enabled, payloadExtractorRerank)
	}
	if http.GenAI.Retrieval.Enabled {
		enabled = append(enabled, payloadExtractorRetrieval)
	}
	if http.GenAI.Ollama.Enabled {
		enabled = append(enabled, payloadExtractorOllama)
	}
	if http.GenAI.Cohere.Enabled {
		enabled = append(enabled, payloadExtractorCohere)
	}
	if http.GenAI.OpenAICompatible.Enabled {
		enabled = append(enabled, payloadExtractorOpenAICompatible)
	}
	if http.JSONRPC.Enabled {
		enabled = append(enabled, payloadExtractorJSONRPC)
	}
	if http.Enrichment.Enabled {
		enabled = append(enabled, payloadExtractorEnrichment)
	}

	return schema.PayloadExtraction{
		Enabled: enabled,
		SQLPP: schema.SQLPPPayload{
			EndpointPatterns:            http.SQLPP.EndpointPatterns,
			PreparedStatementsCacheSize: http.SQLPP.PreparedStatementsCacheSize,
		},
		OpenAICompatible: schema.OpenAICompatiblePayload{
			Gateways: http.GenAI.OpenAICompatible.Gateways,
		},
		Enrichment: httpEnrichment(cfg),
	}
}

func httpEnrichment(cfg *obi.Config) schema.HTTPEnrichment {
	enrichment := cfg.EBPF.PayloadExtraction.HTTP.Enrichment
	return schema.HTTPEnrichment{
		Policy: schema.HTTPEnrichmentPolicy{
			DefaultAction: schema.HTTPEnrichmentDefaultAction{
				Headers: enrichment.Policy.DefaultAction.Headers,
				Body:    enrichment.Policy.DefaultAction.Body,
			},
			DefaultObfuscationString: enrichment.Policy.DefaultObfuscationString,
		},
		Rules: enrichment.Rules,
	}
}

func signalFilters(in filter.AttributeFamilyConfig) schema.SignalFilters {
	return schema.SignalFilters{
		Traces:  filterMap(in),
		Metrics: filterMap(in),
	}
}

func applicationSignalFilters(
	filters filter.AttributesConfig,
	instrumentation instrumentations.Instrumentation,
) schema.SignalFilters {
	scoped, ok := filters.ApplicationByInstrumentation[instrumentation]
	if !ok {
		return signalFilters(filters.Application)
	}
	return schema.SignalFilters{
		Traces:  filterMap(scoped.Traces),
		Metrics: filterMap(scoped.Metrics),
	}
}

func filterMap(in filter.AttributeFamilyConfig) schema.AttributeFilters {
	out := schema.AttributeFilters{}
	for key, def := range in {
		entry := schema.AttributeFilter{}
		if def.Match != "" {
			entry.Match = def.Match
		}
		if def.NotMatch != "" {
			entry.NotMatch = def.NotMatch
		}
		if def.Equals != nil {
			entry.Equals = def.Equals
		}
		if def.NotEquals != nil {
			entry.NotEquals = def.NotEquals
		}
		if def.GreaterEquals != nil {
			entry.GreaterEquals = def.GreaterEquals
		}
		if def.GreaterThan != nil {
			entry.GreaterThan = def.GreaterThan
		}
		if def.LessEquals != nil {
			entry.LessEquals = def.LessEquals
		}
		if def.LessThan != nil {
			entry.LessThan = def.LessThan
		}
		out[key] = entry
	}
	return out
}

func networkFlowEnrichment(cfg *obi.Config) schema.NetworkEnrichment {
	return schema.NetworkEnrichment{
		GeoIP: schema.GeoIPEnrichment{
			IPInfo: schema.Path{
				Path: cfg.NetworkFlows.GeoIP.IPInfo.Path,
			},
			MaxMind: schema.MaxMind{
				CountryPath: cfg.NetworkFlows.GeoIP.MaxMindInfo.CountryPath,
				ASNPath:     cfg.NetworkFlows.GeoIP.MaxMindInfo.ASNPath,
			},
			Cache: schema.Cache{
				Size: cfg.NetworkFlows.GeoIP.CacheLen,
				TTL:  schema.Duration(cfg.NetworkFlows.GeoIP.CacheTTL),
			},
		},
		ReverseDNS: schema.ReverseDNSEnrichment{
			Mode: schema.ReverseDNSMode(cfg.NetworkFlows.ReverseDNS.Type),
			Cache: schema.Cache{
				Size: cfg.NetworkFlows.ReverseDNS.CacheLen,
				TTL:  schema.Duration(cfg.NetworkFlows.ReverseDNS.CacheTTL),
			},
		},
	}
}

func statsEnrichment(cfg *obi.Config) schema.NetworkEnrichment {
	return schema.NetworkEnrichment{
		GeoIP: schema.GeoIPEnrichment{
			IPInfo: schema.Path{
				Path: cfg.Stats.GeoIP.IPInfo.Path,
			},
			MaxMind: schema.MaxMind{
				CountryPath: cfg.Stats.GeoIP.MaxMindInfo.CountryPath,
				ASNPath:     cfg.Stats.GeoIP.MaxMindInfo.ASNPath,
			},
			Cache: schema.Cache{
				Size: cfg.Stats.GeoIP.CacheLen,
				TTL:  schema.Duration(cfg.Stats.GeoIP.CacheTTL),
			},
		},
		ReverseDNS: schema.ReverseDNSEnrichment{
			Mode: schema.ReverseDNSMode(cfg.Stats.ReverseDNS.Type),
			Cache: schema.Cache{
				Size: cfg.Stats.ReverseDNS.CacheLen,
				TTL:  schema.Duration(cfg.Stats.ReverseDNS.CacheTTL),
			},
		},
	}
}

func rulesFromRuntime(cfg *obi.Config) []schema.Rule {
	rules := []schema.Rule{}
	findingCriteria := discover.FindingCriteria(cfg)
	deprecatedServiceSelection := discover.OnlyDefinesDeprecatedServiceSelection(cfg)
	regexSelection := deprecatedServiceSelection || selectorsUseRegex(findingCriteria)
	if deprecatedServiceSelection {
		rules = appendSelectorRules(rules, schema.CaptureActionExclude, discover.RegexAsSelector(cfg.Discovery.ExcludeServices), nil, true)
		rules = appendSelectorRules(rules, schema.CaptureActionExclude, discover.RegexAsSelector(cfg.Discovery.DefaultExcludeServices), defaultExcludeRule, true)
	} else {
		rules = appendSelectorRules(rules, schema.CaptureActionExclude, discover.GlobsAsSelector(cfg.Discovery.ExcludeInstrument), nil, regexSelection)
		rules = appendSelectorRules(rules, schema.CaptureActionExclude, discover.GlobsAsSelector(cfg.Discovery.DefaultExcludeInstrument), defaultExcludeRule, regexSelection)
	}

	if cfg.Discovery.ExcludeOTelInstrumentedServices {
		rules = append(rules, schema.Rule{
			Action:      schema.CaptureActionExclude,
			Name:        "exclude-otlp-exporters",
			Description: "Exclude services that already export OTLP to prevent duplicate telemetry pipelines.",
			Match: schema.RuleMatch{
				Process: schema.RuleProcessMatch{
					ExportsOTLP: &schema.RuleExportsOTLP{
						Port:     cfg.Discovery.DefaultOtlpGRPCPort,
						Protocol: "protobuf",
					},
				},
			},
		})
	}

	includeCriteria := slices.Clone(findingCriteria)
	slices.Reverse(includeCriteria)
	rules = appendSelectorRules(rules, schema.CaptureActionInclude, includeCriteria, nil, regexSelection)

	return rules
}

func selectorsUseRegex(selectors []services.Selector) bool {
	for _, selector := range selectors {
		if ruleUsesRegex(selectorMatch(selector)) {
			return true
		}
	}
	return false
}

type defaultRuleFunc func(int, schema.RuleMatch) (string, string)

func appendSelectorRules(
	rules []schema.Rule,
	action schema.CaptureAction,
	selectors []services.Selector,
	defaultRule defaultRuleFunc,
	regexFamily bool,
) []schema.Rule {
	for i, selector := range selectors {
		match := selectorMatch(selector)
		if regexFamily && ruleUsesGlob(match) {
			match = globRuleMatchAsRegex(match)
		}
		if regexFamily && !ruleMatchEmpty(match) && !ruleUsesRegex(match) {
			match.Process.ExePathRegex = ".*"
		}
		if ruleMatchEmpty(match) {
			continue
		}

		rule := schema.Rule{
			Action: action,
			Match:  match,
		}
		if defaultRule != nil {
			rule.Name, rule.Description = defaultRule(i, match)
		}
		rule.Refine = selectorRefinement(action, selector)
		rules = append(rules, rule)
	}
	return rules
}

func selectorMatch(selector services.Selector) schema.RuleMatch {
	switch selector := selector.(type) {
	case *services.GlobAttributes:
		return globSelectorMatch(selector)
	case *services.RegexSelector:
		return regexSelectorMatch(selector)
	default:
		return schema.RuleMatch{}
	}
}

func globSelectorMatch(selector *services.GlobAttributes) schema.RuleMatch {
	match := schema.RuleMatch{}

	if selector.OpenPorts.Len() > 0 {
		match.Process.OpenPorts = &selector.OpenPorts
	}
	if len(selector.PIDs) > 0 {
		match.Process.TargetPIDs = selector.PIDs
	}
	if selector.Languages.IsSet() {
		match.Process.LanguageGlob = globList(selector.Languages)
	}
	if selector.CmdArgs.IsSet() {
		match.Process.CmdArgsGlob = globList(selector.CmdArgs)
	}
	if selector.Path.IsSet() {
		match.Process.ExePathGlob = globList(selector.Path)
	}
	if selector.ContainersOnly {
		match.Process.ContainersOnly = true
	}

	if namespace := selector.Metadata[services.AttrNamespace]; namespace != nil && namespace.IsSet() {
		match.Kubernetes.NamespaceGlob = globList(*namespace)
	}
	if metadata := globMetadataMap(selector.Metadata); len(metadata) > 0 {
		match.Kubernetes.MetadataGlob = metadata
	}
	if labels := globMap(selector.PodLabels); len(labels) > 0 {
		match.Kubernetes.PodLabels = labels
	}
	if annotations := globMap(selector.PodAnnotations); len(annotations) > 0 {
		match.Kubernetes.PodAnnotations = annotations
	}
	return match
}

func regexSelectorMatch(selector *services.RegexSelector) schema.RuleMatch {
	match := schema.RuleMatch{}

	if selector.OpenPorts.Len() > 0 {
		match.Process.OpenPorts = &selector.OpenPorts
	}
	if len(selector.PIDs) > 0 {
		match.Process.TargetPIDs = selector.PIDs
	}
	if selector.Languages.IsSet() {
		match.Process.LanguageRegex = regexString(selector.Languages)
	}
	if selector.CmdArgs.IsSet() {
		match.Process.CmdArgsRegex = regexString(selector.CmdArgs)
	}
	switch {
	case selector.Path.IsSet():
		match.Process.ExePathRegex = regexString(selector.Path)
	case selector.PathRegexp.IsSet():
		match.Process.ExePathRegex = regexString(selector.PathRegexp)
	}
	if selector.ContainersOnly {
		match.Process.ContainersOnly = true
	}

	if namespace := selector.Metadata[services.AttrNamespace]; namespace != nil && namespace.IsSet() {
		match.Kubernetes.NamespaceRegex = regexString(*namespace)
	}
	if metadata := regexMetadataMap(selector.Metadata); len(metadata) > 0 {
		match.Kubernetes.MetadataRegex = metadata
	}
	if labels := regexMap(selector.PodLabels); len(labels) > 0 {
		match.Kubernetes.PodLabelsRegex = labels
	}
	if annotations := regexMap(selector.PodAnnotations); len(annotations) > 0 {
		match.Kubernetes.PodAnnotationsRegex = annotations
	}
	return match
}

func selectorRefinement(action schema.CaptureAction, selector services.Selector) schema.RuleRefinement {
	refine := schema.RuleRefinement{}
	if action != schema.CaptureActionInclude {
		return refine
	}
	if exports := exportModeRefinement(selector.GetExportModes()); exports != nil {
		refine.Exports = exports
	}
	if routes := selector.GetRoutesConfig(); routes != nil &&
		(routes.PolicyOverrides != nil || len(routes.Incoming) > 0 || len(routes.Outgoing) > 0) {
		refinementRoutes := schema.HTTPRefinementRoutes{}
		if routes.PolicyOverrides != nil {
			refinementRoutes.Incoming = httpRoutePolicyOverride(routes.PolicyOverrides.Incoming)
			refinementRoutes.Outgoing = httpRoutePolicyOverride(routes.PolicyOverrides.Outgoing)
		} else {
			if len(routes.Incoming) > 0 {
				patterns := cloneStrings(routes.Incoming)
				refinementRoutes.Incoming = &schema.HTTPRoutePolicy{Patterns: &patterns}
			}
			if len(routes.Outgoing) > 0 {
				patterns := cloneStrings(routes.Outgoing)
				refinementRoutes.Outgoing = &schema.HTTPRoutePolicy{Patterns: &patterns}
			}
		}
		refine.HTTP = &schema.HTTPRefinement{
			Routes: refinementRoutes,
		}
	}
	return refine
}

func httpRoutePolicyOverride(policy *services.RoutePolicyOverride) *schema.HTTPRoutePolicy {
	if policy == nil {
		return nil
	}
	return &schema.HTTPRoutePolicy{
		Unmatched:                 cloneValue(policy.Unmatch),
		Patterns:                  cloneStringsPointer(policy.Patterns),
		IgnoredPatterns:           cloneStringsPointer(policy.IgnorePatterns),
		IgnoreMode:                cloneValue(policy.IgnoredEvents),
		WildcardChar:              cloneValue(policy.WildcardChar),
		MaxPathSegmentCardinality: cloneValue(policy.MaxPathSegmentCardinality),
	}
}

func exportModeRefinement(modes services.ExportModes) *schema.ExportModeRefinement {
	if modes == services.ExportModeUnset {
		return nil
	}
	return &schema.ExportModeRefinement{
		Logs:    modes.CanExportLogs(),
		Traces:  modes.CanExportTraces(),
		Metrics: modes.CanExportMetrics(),
	}
}

func defaultExcludeRule(index int, match schema.RuleMatch) (string, string) {
	if index == 0 {
		return "exclude-obi-and-collectors",
			"Exclude OBI and collector binaries to avoid self-instrumentation and collector recursion."
	}
	if index == 1 {
		return "exclude-system-namespaces",
			"Exclude common platform/system Kubernetes namespaces from instrumentation by default."
	}
	if !ruleKubernetesMatchEmpty(match.Kubernetes) {
		return "exclude-system-namespaces",
			"Exclude common platform/system Kubernetes namespaces from instrumentation by default."
	}
	return "exclude-obi-and-collectors",
		"Exclude OBI and collector binaries to avoid self-instrumentation and collector recursion."
}

func ruleMatchEmpty(match schema.RuleMatch) bool {
	return ruleProcessMatchEmpty(match.Process) && ruleKubernetesMatchEmpty(match.Kubernetes)
}

func ruleProcessMatchEmpty(match schema.RuleProcessMatch) bool {
	return match.OpenPorts == nil &&
		len(match.TargetPIDs) == 0 &&
		len(match.LanguageGlob) == 0 &&
		match.LanguageRegex == "" &&
		len(match.CmdArgsGlob) == 0 &&
		match.CmdArgsRegex == "" &&
		len(match.ExePathGlob) == 0 &&
		match.ExePathRegex == "" &&
		!match.ContainersOnly &&
		match.ExportsOTLP == nil
}

func ruleKubernetesMatchEmpty(match schema.RuleKubernetesMatch) bool {
	return len(match.NamespaceGlob) == 0 &&
		match.NamespaceRegex == "" &&
		len(match.MetadataGlob) == 0 &&
		len(match.MetadataRegex) == 0 &&
		len(match.PodLabels) == 0 &&
		len(match.PodLabelsRegex) == 0 &&
		len(match.PodAnnotations) == 0 &&
		len(match.PodAnnotationsRegex) == 0
}

func globMap(values map[string]*services.GlobAttr) map[string][]string {
	out := make(map[string][]string, len(values))
	for key, value := range values {
		if value == nil || !value.IsSet() {
			continue
		}
		out[key] = globList(*value)
	}
	return out
}

func globMetadataMap(values services.MetadataGlobMap) map[string][]string {
	out := make(map[string][]string, len(values))
	for key, value := range values {
		if key == services.AttrNamespace || value == nil || !value.IsSet() {
			continue
		}
		out[key] = globList(*value)
	}
	return out
}

func globList(value services.GlobAttr) []string {
	raw := globString(value)
	if raw == "" {
		return nil
	}
	tree, err := syntax.Parse(raw)
	if err != nil || len(tree.Children) != 1 || tree.Children[0].Kind != ast.KindAnyOf {
		return []string{raw}
	}

	alternatives := make([]string, 0, len(tree.Children[0].Children))
	for _, alternative := range tree.Children[0].Children {
		if alternative.Kind != ast.KindPattern || len(alternative.Children) != 1 || alternative.Children[0].Kind != ast.KindText {
			return []string{raw}
		}
		text := alternative.Children[0].Value.(ast.Text).Text
		for i := 0; i < len(text); i++ {
			if syntax.Special(text[i]) {
				return []string{raw}
			}
		}
		alternatives = append(alternatives, text)
	}
	return alternatives
}

func globRuleMatchAsRegex(match schema.RuleMatch) schema.RuleMatch {
	match.Process.LanguageRegex = globPatternsRegex(match.Process.LanguageGlob)
	match.Process.LanguageGlob = nil
	match.Process.CmdArgsRegex = globPatternsRegex(match.Process.CmdArgsGlob)
	match.Process.CmdArgsGlob = nil
	match.Process.ExePathRegex = globPatternsRegex(match.Process.ExePathGlob)
	match.Process.ExePathGlob = nil

	match.Kubernetes.NamespaceRegex = globPatternsRegex(match.Kubernetes.NamespaceGlob)
	match.Kubernetes.NamespaceGlob = nil
	match.Kubernetes.MetadataRegex = globPatternMapRegex(match.Kubernetes.MetadataGlob)
	match.Kubernetes.MetadataGlob = nil
	match.Kubernetes.PodLabelsRegex = globPatternMapRegex(match.Kubernetes.PodLabels)
	match.Kubernetes.PodLabels = nil
	match.Kubernetes.PodAnnotationsRegex = globPatternMapRegex(match.Kubernetes.PodAnnotations)
	match.Kubernetes.PodAnnotations = nil

	return match
}

func globPatternMapRegex(patterns map[string][]string) map[string]string {
	if len(patterns) == 0 {
		return nil
	}

	out := make(map[string]string, len(patterns))
	for key, values := range patterns {
		out[key] = globPatternsRegex(values)
	}
	return out
}

func globPatternsRegex(patterns []string) string {
	if len(patterns) == 0 {
		return ""
	}

	converted := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		tree, err := syntax.Parse(pattern)
		if err != nil {
			panic("validated glob could not be parsed: " + err.Error())
		}
		var expression strings.Builder
		writeGlobNodeRegex(&expression, tree)
		converted = append(converted, expression.String())
	}
	return `(?s)^(?:` + strings.Join(converted, "|") + `)$`
}

func writeGlobNodeRegex(expression *strings.Builder, node *ast.Node) {
	switch node.Kind {
	case ast.KindNothing:
	case ast.KindPattern:
		for _, child := range node.Children {
			writeGlobNodeRegex(expression, child)
		}
	case ast.KindList:
		list := node.Value.(ast.List)
		expression.WriteByte('[')
		if list.Not {
			expression.WriteByte('^')
		}
		writeRegexClass(expression, []rune(list.Chars))
		expression.WriteByte(']')
	case ast.KindRange:
		rangeValue := node.Value.(ast.Range)
		expression.WriteByte('[')
		if rangeValue.Not {
			expression.WriteByte('^')
		}
		writeRegexClass(expression, []rune{rangeValue.Lo})
		expression.WriteByte('-')
		writeRegexClass(expression, []rune{rangeValue.Hi})
		expression.WriteByte(']')
	case ast.KindText:
		expression.WriteString(regexp.QuoteMeta(node.Value.(ast.Text).Text))
	case ast.KindAny, ast.KindSuper:
		expression.WriteString(".*")
	case ast.KindSingle:
		expression.WriteByte('.')
	case ast.KindAnyOf:
		expression.WriteString("(?:")
		for i, child := range node.Children {
			if i > 0 {
				expression.WriteByte('|')
			}
			writeGlobNodeRegex(expression, child)
		}
		expression.WriteByte(')')
	default:
		panic("unsupported glob syntax node")
	}
}

func writeRegexClass(expression *strings.Builder, values []rune) {
	for _, value := range values {
		expression.WriteString(`\x{`)
		expression.WriteString(strconv.FormatInt(int64(value), 16))
		expression.WriteByte('}')
	}
}

func globString(g services.GlobAttr) string {
	value, err := g.MarshalYAML()
	if err != nil {
		return ""
	}
	if str, ok := value.(string); ok {
		return str
	}
	return ""
}

func regexMap(values map[string]*services.RegexpAttr) map[string]string {
	out := make(map[string]string, len(values))
	for key, value := range values {
		if value == nil || !value.IsSet() {
			continue
		}
		out[key] = regexString(*value)
	}
	return out
}

func regexMetadataMap(values services.MetadataRegexMap) map[string]string {
	out := make(map[string]string, len(values))
	for key, value := range values {
		if key == services.AttrNamespace || value == nil || !value.IsSet() {
			continue
		}
		out[key] = regexString(*value)
	}
	return out
}

func regexString(r services.RegexpAttr) string {
	value, err := r.MarshalYAML()
	if err != nil {
		return ""
	}
	if str, ok := value.(string); ok {
		return str
	}
	return ""
}

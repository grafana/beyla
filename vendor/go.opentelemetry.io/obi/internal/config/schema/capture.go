// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schema // import "go.opentelemetry.io/obi/internal/config/schema"

import (
	"go.yaml.in/yaml/v3"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export/attributes"
)

// Capture contains receiver-embeddable OBI capture settings.
//
// Known capture sections are typed so exporter-owned fields and nesting have
// compile-time coverage.
type Capture struct {
	Attributes      *CaptureAttributes        `yaml:"attributes,omitempty"`
	Exceptions      services.ExceptionsConfig `yaml:"exceptions"`
	Policy          CapturePolicy             `yaml:"policy"`
	Rules           []Rule                    `yaml:"rules"`
	Instrumentation Instrumentation           `yaml:"instrumentation"`
	Runtimes        CaptureRuntimes           `yaml:"runtimes"`
	Network         CaptureNetwork            `yaml:"network"`
	Metrics         CaptureMetrics            `yaml:"metrics"`
	Limits          CaptureLimits             `yaml:"limits"`
	Engine          CaptureEngine             `yaml:"engine"`
	Safety          CaptureSafety             `yaml:"safety"`
	Channels        CaptureChannels           `yaml:"channels"`
	Telemetry       CaptureTelemetry          `yaml:"telemetry"`
}

// CaptureAttributes selects supported fields while OBI constructs telemetry.
type CaptureAttributes struct {
	Select attributes.Selection `yaml:"select"`
}

// MatchOrder describes how capture rules are evaluated when multiple rules
// match.
type MatchOrder string

const (
	// MatchOrderFirstMatchWins stops evaluation at the first matching rule.
	MatchOrderFirstMatchWins MatchOrder = "first_match_wins"
	// MatchOrderLastMatchWins lets the last matching rule decide the action.
	MatchOrderLastMatchWins MatchOrder = "last_match_wins"
)

// UnmarshalYAML parses and validates a capture rule match order.
func (m *MatchOrder) UnmarshalYAML(value *yaml.Node) error {
	return unmarshalEnum(value, "match_order", m, MatchOrderFirstMatchWins, MatchOrderLastMatchWins)
}

// CaptureAction describes whether a capture rule includes or excludes a
// matched target.
type CaptureAction string

const (
	// CaptureActionInclude enables capture for matching targets.
	CaptureActionInclude CaptureAction = "include"
	// CaptureActionExclude disables capture for matching targets.
	CaptureActionExclude CaptureAction = "exclude"
)

// UnmarshalYAML parses and validates a capture action.
func (a *CaptureAction) UnmarshalYAML(value *yaml.Node) error {
	return unmarshalEnum(value, "action", a, CaptureActionInclude, CaptureActionExclude)
}

// CapturePolicy describes the default action and process discovery timing for
// capture rule evaluation.
type CapturePolicy struct {
	DefaultAction CaptureAction `yaml:"default_action"`
	MatchOrder    MatchOrder    `yaml:"match_order"`
	PollInterval  Duration      `yaml:"poll_interval"`
	MinProcessAge Duration      `yaml:"min_process_age"`
}

// Rule describes one capture policy rule.
type Rule struct {
	Action               CaptureAction  `yaml:"action"`
	Name                 string         `yaml:"name"`
	Description          string         `yaml:"description"`
	Match                RuleMatch      `yaml:"match"`
	Refine               RuleRefinement `yaml:"refine,omitempty"`
	AdditionalProperties map[string]any `yaml:",inline"`
}

// RuleRefinement holds per-rule overrides that apply after a rule matches.
type RuleRefinement struct {
	Exceptions *services.ExceptionsOverride `yaml:"exceptions,omitempty"`
	Exports    *ExportModeRefinement        `yaml:"exports,omitempty"`
	HTTP       *HTTPRefinement              `yaml:"http,omitempty"`
}

// ExportModeRefinement overrides trace and metric exports for a matched rule.
type ExportModeRefinement struct {
	Logs    bool `yaml:"logs,omitempty"`
	Traces  bool `yaml:"traces"`
	Metrics bool `yaml:"metrics"`
}

// RuleMatch contains process and Kubernetes selectors for a capture rule.
type RuleMatch struct {
	Process              RuleProcessMatch    `yaml:"process,omitempty"`
	Kubernetes           RuleKubernetesMatch `yaml:"kubernetes,omitempty"`
	AdditionalProperties map[string]any      `yaml:",inline"`
}

// RuleProcessMatch describes process-level predicates for a capture rule.
type RuleProcessMatch struct {
	OpenPorts            *services.IntEnum `yaml:"open_ports,omitempty"`
	TargetPIDs           []uint32          `yaml:"target_pids,omitempty"`
	LanguageGlob         []string          `yaml:"language_glob,omitempty"`
	LanguageRegex        string            `yaml:"language_regex,omitempty"`
	CmdArgsGlob          []string          `yaml:"cmd_args_glob,omitempty"`
	CmdArgsRegex         string            `yaml:"cmd_args_regex,omitempty"`
	ExePathGlob          []string          `yaml:"exe_path_glob,omitempty"`
	ExePathRegex         string            `yaml:"exe_path_regex,omitempty"`
	ContainersOnly       bool              `yaml:"containers_only,omitempty"`
	ExportsOTLP          *RuleExportsOTLP  `yaml:"exports_otlp,omitempty"`
	AdditionalProperties map[string]any    `yaml:",inline"`
}

// RuleExportsOTLP matches processes exporting OTLP on a known port and
// protocol.
type RuleExportsOTLP struct {
	Port     int    `yaml:"port"`
	Protocol string `yaml:"protocol"`
}

// RuleKubernetesMatch describes Kubernetes metadata predicates for a capture
// rule.
type RuleKubernetesMatch struct {
	NamespaceGlob        []string            `yaml:"namespace_glob,omitempty"`
	NamespaceRegex       string              `yaml:"namespace_regex,omitempty"`
	MetadataGlob         map[string][]string `yaml:"metadata_glob,omitempty"`
	MetadataRegex        map[string]string   `yaml:"metadata_regex,omitempty"`
	PodLabels            map[string][]string `yaml:"pod_labels,omitempty"`
	PodLabelsRegex       map[string]string   `yaml:"pod_labels_regex,omitempty"`
	PodAnnotations       map[string][]string `yaml:"pod_annotations,omitempty"`
	PodAnnotationsRegex  map[string]string   `yaml:"pod_annotations_regex,omitempty"`
	AdditionalProperties map[string]any      `yaml:",inline"`
}

// HTTPRefinement contains per-rule HTTP route and filter overrides.
type HTTPRefinement struct {
	Routes  HTTPRefinementRoutes `yaml:"routes,omitempty"`
	Filters SignalFilters        `yaml:"filters,omitempty"`
}

// HTTPRefinementRoutes groups incoming and outgoing per-rule route policies.
type HTTPRefinementRoutes struct {
	Incoming *HTTPRoutePolicy `yaml:"incoming,omitempty"`
	Outgoing *HTTPRoutePolicy `yaml:"outgoing,omitempty"`
}

// CaptureLimits describes capture cardinality and buffering limits.
type CaptureLimits struct {
	NetworkPackets  int `yaml:"network_packets"`
	MetricSpanNames int `yaml:"metric_span_names"`
}

// CaptureSafety describes runtime safety requirements for capture.
type CaptureSafety struct {
	EnforceSystemCapabilities bool `yaml:"enforce_system_capabilities"`
}

// CaptureChannels describes internal event channel settings.
type CaptureChannels struct {
	BufferLen          int      `yaml:"buffer_len"`
	SendTimeout        Duration `yaml:"send_timeout"`
	PanicOnSendTimeout bool     `yaml:"panic_on_send_timeout"`
}

// CaptureTelemetry describes internal capture telemetry settings.
type CaptureTelemetry struct {
	Traces  TracesTelemetry  `yaml:"traces"`
	Metrics MetricsTelemetry `yaml:"metrics"`
}

// TracesTelemetry describes trace pipeline telemetry settings.
type TracesTelemetry struct {
	ReportersCacheLen int `yaml:"reporters_cache_len"`
}

// MetricsTelemetry describes metric pipeline telemetry settings.
type MetricsTelemetry struct {
	ReportersCacheLen int      `yaml:"reporters_cache_len"`
	TTL               Duration `yaml:"ttl"`
	// ConnectionInfoTTL controls how long observed connection-info edges remain active.
	ConnectionInfoTTL Duration `yaml:"connection_info_ttl"`
}

// CaptureMetrics selects the metric families emitted by OBI.
type CaptureMetrics struct {
	Features []string `yaml:"features"`
}

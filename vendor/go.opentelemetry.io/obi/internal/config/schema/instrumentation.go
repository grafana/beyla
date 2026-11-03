// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schema // import "go.opentelemetry.io/obi/internal/config/schema"

import (
	"go.yaml.in/yaml/v3"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/config"
)

// Instrumentation groups protocol-specific capture settings.
type Instrumentation struct {
	HTTP      HTTPInstrumentation       `yaml:"http"`
	GRPC      ProtocolInstrumentation   `yaml:"grpc"`
	SQL       SQLInstrumentation        `yaml:"sql"`
	Redis     RedisInstrumentation      `yaml:"redis"`
	Kafka     KafkaInstrumentation      `yaml:"kafka"`
	Mongo     MongoInstrumentation      `yaml:"mongo"`
	Couchbase CouchbaseInstrumentation  `yaml:"couchbase"`
	DNS       DNSInstrumentation        `yaml:"dns"`
	GPU       GPUInstrumentation        `yaml:"gpu"`
	Aerospike *AerospikeInstrumentation `yaml:"aerospike,omitempty"`
}

// ProtocolInstrumentation describes common trace and metric enablement and
// filtering for protocols without additional protocol-specific settings.
type ProtocolInstrumentation struct {
	Enabled ProtocolEnablement `yaml:"enabled"`
	Filters SignalFilters      `yaml:"filters"`
}

// AerospikeInstrumentation applies the documented signal defaults when the
// optional Aerospike section is present but incomplete.
type AerospikeInstrumentation struct {
	Enabled    ProtocolEnablement `yaml:"enabled"`
	Filters    SignalFilters      `yaml:"filters"`
	BufferSize uint32             `yaml:"buffer_size"`
}

// UnmarshalYAML defaults omitted Aerospike signal fields to enabled.
func (a *AerospikeInstrumentation) UnmarshalYAML(value *yaml.Node) error {
	type plain AerospikeInstrumentation
	decoded := plain{Enabled: ProtocolEnablement{Traces: true, Metrics: true}}
	if err := decodeKnownFields(value, &decoded); err != nil {
		return err
	}
	*a = AerospikeInstrumentation(decoded)
	return nil
}

// ProtocolEnablement selects whether a protocol emits traces and metrics.
type ProtocolEnablement struct {
	Traces  bool `yaml:"traces"`
	Metrics bool `yaml:"metrics"`
}

// HTTPProtocolEnablement adds the HTTP-only body size histograms to the shared
// traces and metrics switches. They are Opt-In in the semantic conventions, and
// they only exist for HTTP, so they are not part of ProtocolEnablement.
type HTTPProtocolEnablement struct {
	ProtocolEnablement `yaml:",inline"`

	BodySizeMetrics bool `yaml:"body_size_metrics"`
}

// HTTPInstrumentation describes HTTP capture, filtering, route, and payload
// extraction settings.
type HTTPInstrumentation struct {
	Enabled                   HTTPProtocolEnablement `yaml:"enabled"`
	Filters                   SignalFilters          `yaml:"filters"`
	TrackRequestHeaders       bool                   `yaml:"track_request_headers"`
	RequestTimeout            Duration               `yaml:"request_timeout"`
	GoHTTPClientBufferTimeout Duration               `yaml:"go_http_client_buffer_timeout"`
	BufferSize                uint32                 `yaml:"buffer_size"`
	Routes                    HTTPRoutes             `yaml:"routes"`
	PayloadExtraction         PayloadExtraction      `yaml:"payload_extraction"`
}

// HTTPRoutes describes directional global HTTP route normalization and discovery settings.
type HTTPRoutes struct {
	Incoming  *HTTPRoutePolicy   `yaml:"incoming,omitempty"`
	Outgoing  *HTTPRoutePolicy   `yaml:"outgoing,omitempty"`
	Discovery HTTPRouteDiscovery `yaml:"discovery"`
}

// HTTPRoutePolicy configures route handling for one traffic direction.
type HTTPRoutePolicy struct {
	Unmatched                 *services.RouteUnmatch    `yaml:"unmatched,omitempty"`
	Patterns                  *[]string                 `yaml:"patterns,omitempty"`
	IgnoredPatterns           *[]string                 `yaml:"ignored_patterns,omitempty"`
	IgnoreMode                *services.RouteIgnoreMode `yaml:"ignore_mode,omitempty"`
	WildcardChar              *string                   `yaml:"wildcard_char,omitempty"`
	MaxPathSegmentCardinality *int                      `yaml:"max_path_segment_cardinality,omitempty"`
}

// HTTPRouteDiscovery describes automatic HTTP route discovery settings.
type HTTPRouteDiscovery struct {
	Timeout           Duration                          `yaml:"timeout"`
	DisabledLanguages []services.RouteHarvesterLanguage `yaml:"disabled_languages"`
	Java              HTTPRouteJavaDiscovery            `yaml:"java"`
}

// HTTPRouteJavaDiscovery describes Java-specific HTTP route discovery timing.
type HTTPRouteJavaDiscovery struct {
	Delay Duration `yaml:"delay"`
}

// SQLInstrumentation describes SQL capture and database-specific buffering
// settings.
type SQLInstrumentation struct {
	Enabled           ProtocolEnablement         `yaml:"enabled"`
	Filters           SignalFilters              `yaml:"filters"`
	HeuristicDetect   bool                       `yaml:"heuristic_detect"`
	SanitizeQueryText bool                       `yaml:"sanitize_query_text"`
	MySQL             SQLDatabaseInstrumentation `yaml:"mysql"`
	Postgres          SQLDatabaseInstrumentation `yaml:"postgres"`
	MSSQL             SQLDatabaseInstrumentation `yaml:"mssql"`
}

// SQLDatabaseInstrumentation describes capture buffers and prepared statement
// cache sizing for one SQL database family.
type SQLDatabaseInstrumentation struct {
	BufferSize                  uint32 `yaml:"buffer_size"`
	PreparedStatementsCacheSize int    `yaml:"prepared_statements_cache_size"`
}

// RedisInstrumentation describes Redis capture settings.
type RedisInstrumentation struct {
	Enabled ProtocolEnablement `yaml:"enabled"`
	Filters SignalFilters      `yaml:"filters"`
	DBCache RedisDBCache       `yaml:"db_cache"`
}

// RedisDBCache describes Redis database cache behavior.
type RedisDBCache struct {
	Enabled bool `yaml:"enabled"`
	MaxSize int  `yaml:"max_size"`
}

// KafkaInstrumentation describes Kafka capture settings.
type KafkaInstrumentation struct {
	Enabled            ProtocolEnablement `yaml:"enabled"`
	Filters            SignalFilters      `yaml:"filters"`
	BufferSize         uint32             `yaml:"buffer_size"`
	TopicUUIDCacheSize int                `yaml:"topic_uuid_cache_size"`
}

// MongoInstrumentation describes MongoDB capture settings.
type MongoInstrumentation struct {
	Enabled           ProtocolEnablement `yaml:"enabled"`
	Filters           SignalFilters      `yaml:"filters"`
	RequestsCacheSize int                `yaml:"requests_cache_size"`
}

// CouchbaseInstrumentation describes Couchbase capture settings.
type CouchbaseInstrumentation struct {
	Enabled     ProtocolEnablement `yaml:"enabled"`
	Filters     SignalFilters      `yaml:"filters"`
	DBCacheSize int                `yaml:"db_cache_size"`
}

// DNSInstrumentation describes DNS capture settings.
type DNSInstrumentation struct {
	Enabled        ProtocolEnablement `yaml:"enabled"`
	Filters        SignalFilters      `yaml:"filters"`
	RequestTimeout Duration           `yaml:"request_timeout"`
}

// GPUInstrumentation describes GPU capture settings.
type GPUInstrumentation struct {
	Enabled     ProtocolEnablement `yaml:"enabled"`
	Filters     SignalFilters      `yaml:"filters"`
	EnabledMode config.CudaMode    `yaml:"enabled_mode"`
}

// SignalFilters groups attribute filters by telemetry signal.
type SignalFilters struct {
	Traces  AttributeFilters `yaml:"traces"`
	Metrics AttributeFilters `yaml:"metrics"`
}

// AttributeFilters maps attribute names to their filter predicates.
type AttributeFilters map[string]AttributeFilter

// AttributeFilter describes one attribute predicate used to keep matching
// telemetry.
type AttributeFilter struct {
	Match         string `yaml:"match,omitempty"`
	NotMatch      string `yaml:"not_match,omitempty"`
	Equals        *int   `yaml:"equals,omitempty"`
	NotEquals     *int   `yaml:"not_equals,omitempty"`
	GreaterEquals *int   `yaml:"greater_equals,omitempty"`
	GreaterThan   *int   `yaml:"greater_than,omitempty"`
	LessEquals    *int   `yaml:"less_equals,omitempty"`
	LessThan      *int   `yaml:"less_than,omitempty"`
}

// PayloadExtraction describes HTTP payload extractor enablement and enrichment
// settings.
type PayloadExtraction struct {
	Enabled          []string                `yaml:"enabled"`
	SQLPP            SQLPPPayload            `yaml:"sqlpp"`
	Enrichment       HTTPEnrichment          `yaml:"enrichment"`
	OpenAICompatible OpenAICompatiblePayload `yaml:"openai_compatible"`
}

// SQLPPPayload describes SQL++ payload extraction settings.
type SQLPPPayload struct {
	EndpointPatterns            []string `yaml:"endpoint_patterns"`
	PreparedStatementsCacheSize int      `yaml:"prepared_statements_cache_size"`
}

// HTTPEnrichment describes HTTP payload enrichment policy and rules.
type HTTPEnrichment struct {
	Policy HTTPEnrichmentPolicy     `yaml:"policy"`
	Rules  []config.HTTPParsingRule `yaml:"rules"`
}

// UnmarshalYAML keeps the enrichment object strict while accepting the
// implementation-specific properties allowed inside each rule.
func (e *HTTPEnrichment) UnmarshalYAML(value *yaml.Node) error {
	var decoded struct {
		Policy HTTPEnrichmentPolicy `yaml:"policy"`
		Rules  yaml.Node            `yaml:"rules"`
	}
	if err := decodeKnownFields(value, &decoded); err != nil {
		return err
	}

	var rules []config.HTTPParsingRule
	if decoded.Rules.Kind != 0 {
		if err := decode(&decoded.Rules, &rules); err != nil {
			return err
		}
	}
	e.Policy = decoded.Policy
	e.Rules = rules
	return nil
}

// HTTPEnrichmentPolicy describes default HTTP payload enrichment actions.
type HTTPEnrichmentPolicy struct {
	DefaultAction            HTTPEnrichmentDefaultAction `yaml:"default_action"`
	DefaultObfuscationString string                      `yaml:"obfuscation_string"`
}

// HTTPEnrichmentDefaultAction describes default enrichment actions for headers
// and body content.
type HTTPEnrichmentDefaultAction struct {
	Headers config.HTTPParsingAction `yaml:"headers"`
	Body    config.HTTPParsingAction `yaml:"body"`
}

// OpenAICompatiblePayload describes OpenAI-compatible gateway payload extraction
// settings.
type OpenAICompatiblePayload struct {
	Gateways []config.OpenAICompatibleGateway `yaml:"gateways"`
}

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config // import "go.opentelemetry.io/obi/pkg/config"

import (
	"fmt"
	"strings"

	"github.com/invopop/jsonschema"
	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/appolly/services"
)

type PayloadExtraction struct {
	HTTP HTTPConfig `yaml:"http"`
}

func (p PayloadExtraction) Enabled() bool {
	return p.HTTP.GraphQL.Enabled ||
		p.HTTP.Elasticsearch.Enabled ||
		p.HTTP.AWS.Enabled ||
		p.HTTP.SQLPP.Enabled ||
		p.HTTP.OpenAI.Enabled ||
		p.HTTP.Enrichment.Enabled
}

type HTTPConfig struct {
	// GraphQL payload extraction and parsing
	GraphQL GraphQLConfig `yaml:"graphql"`
	// Elasticsearch payload extraction and parsing
	Elasticsearch ElasticsearchConfig `yaml:"elasticsearch"`
	// AWS payload extraction and parsing
	AWS AWSConfig `yaml:"aws"`
	// SQL++ payload extraction and parsing (Couchbase and other SQL++ databases)
	SQLPP SQLPPConfig `yaml:"sqlpp"`
	// OpenAI payload extraction
	OpenAI OpenAIConfig `yaml:"openai"`
	// Enrichment configures HTTP header and payload extraction with policy-based rules
	Enrichment EnrichmentConfig `yaml:"enrichment"`
}

type GraphQLConfig struct {
	// Enable GraphQL payload extraction and parsing
	Enabled bool `yaml:"enabled" env:"OTEL_EBPF_HTTP_GRAPHQL_ENABLED" validate:"boolean"`
}

type AWSConfig struct {
	// Enable AWS services (S3, SQS, etc.) payload extraction and parsing
	Enabled bool `yaml:"enabled" env:"OTEL_EBPF_HTTP_AWS_ENABLED" validate:"boolean"`
}

type ElasticsearchConfig struct {
	// Enable Elasticsearch payload extraction and parsing
	Enabled bool `yaml:"enabled" env:"OTEL_EBPF_HTTP_ELASTICSEARCH_ENABLED" validate:"boolean"`
}

type SQLPPConfig struct {
	// Enable SQL++ payload extraction and parsing
	Enabled bool `yaml:"enabled" env:"OTEL_EBPF_HTTP_SQLPP_ENABLED" validate:"boolean"`
	// EndpointPatterns specifies URL path patterns to detect SQL++ endpoints
	// Example: ["/query/service", "/query"]
	EndpointPatterns []string `yaml:"endpoint_patterns" env:"OTEL_EBPF_HTTP_SQLPP_ENDPOINT_PATTERNS"`
}

type OpenAIConfig struct {
	// Enable OpenAI payload extraction and parsing
	Enabled bool `yaml:"enabled" env:"OTEL_EBPF_HTTP_OPENAI_ENABLED" validate:"boolean"`
}

// EnrichmentConfig configures HTTP header and payload extraction with policy-based rules.
type EnrichmentConfig struct {
	// Enable HTTP header and payload enrichment
	Enabled bool `yaml:"enabled" env:"OTEL_EBPF_HTTP_ENRICHMENT_ENABLED" validate:"boolean"`
	// Policy controls the default behavior and matching strategy
	Policy HTTPParsingPolicy `yaml:"policy"`
	// Rules is an ordered list of include/exclude/obfuscate rules.
	// Rules are evaluated according to Policy.MatchOrder.
	Rules []HTTPParsingRule `yaml:"rules"`
}

// HTTPParsingPolicy defines the default action and match strategy for http enrichment rules.
type HTTPParsingPolicy struct {
	// DefaultAction specifies what to do when no rule matches: "include" or "exclude"
	DefaultAction HTTPParsingAction `yaml:"default_action" env:"OTEL_EBPF_HTTP_ENRICHMENT_DEFAULT_ACTION"`
	// MatchOrder controls how rules are evaluated: "first_match_wins"
	MatchOrder HTTPParsingMatchOrder `yaml:"match_order" env:"OTEL_EBPF_HTTP_ENRICHMENT_MATCH_ORDER"`
	// ObfuscationString is the replacement string used when a rule's action is "obfuscate"
	ObfuscationString string `yaml:"obfuscation_string" env:"OTEL_EBPF_HTTP_ENRICHMENT_OBFUSCATION_STRING"`
}

// HTTPParsingRule defines a single include/exclude/obfuscate rule for HTTP header and payload extraction.
type HTTPParsingRule struct {
	// Action of the rule: "include", "exclude", or "obfuscate"
	Action HTTPParsingAction `yaml:"action"`
	// Type specifies what this rule matches against: "headers"
	Type HTTPParsingRuleType `yaml:"type"`
	// Scope of the rule: "request", "response", or "all"
	Scope HTTPParsingScope `yaml:"scope"`
	// Match defines the matching criteria for this rule
	Match HTTPParsingMatch `yaml:"match"`
}

// HTTPParsingRuleType specifies the target of a parsing rule.
type HTTPParsingRuleType uint8

const (
	HTTPParsingRuleTypeHeaders HTTPParsingRuleType = iota + 1
)

func (t *HTTPParsingRuleType) UnmarshalText(text []byte) error {
	switch strings.TrimSpace(string(text)) {
	case "headers":
		*t = HTTPParsingRuleTypeHeaders
		return nil
	default:
		return fmt.Errorf("invalid parsing rule type: %q (valid: headers)", string(text))
	}
}

func (t HTTPParsingRuleType) MarshalText() ([]byte, error) {
	switch t {
	case HTTPParsingRuleTypeHeaders:
		return []byte("headers"), nil
	default:
		return nil, fmt.Errorf("unknown parsing rule type: %d", t)
	}
}

func (HTTPParsingRuleType) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"headers"},
	}
}

// HTTPParsingMatch defines matching criteria for an HTTP parsing rule.
type HTTPParsingMatch struct {
	// Patterns is a list of glob patterns to match the rule against
	Patterns []services.GlobAttr `yaml:"patterns"`
	// CaseSensitive controls whether matching is case-sensitive.
	CaseSensitive bool `yaml:"case_sensitive"`
}

// UnmarshalYAML deserializes the match config and compiles glob patterns.
func (m *HTTPParsingMatch) UnmarshalYAML(value *yaml.Node) error {
	var raw struct {
		Patterns      []string `yaml:"patterns"`
		CaseSensitive bool     `yaml:"case_sensitive"`
	}
	if err := value.Decode(&raw); err != nil {
		return err
	}

	m.CaseSensitive = raw.CaseSensitive
	m.Patterns = make([]services.GlobAttr, 0, len(raw.Patterns))
	for _, pattern := range raw.Patterns {
		compilePattern := pattern
		if !m.CaseSensitive {
			compilePattern = strings.ToLower(pattern)
		}
		m.Patterns = append(m.Patterns, services.NewGlob(compilePattern))
	}
	return nil
}

// HTTPParsingAction represents the action for a generic parsing rule or default policy.
type HTTPParsingAction uint8

const (
	HTTPParsingActionInclude HTTPParsingAction = iota + 1
	HTTPParsingActionExclude
	HTTPParsingActionObfuscate
)

func (a *HTTPParsingAction) UnmarshalText(text []byte) error {
	switch strings.TrimSpace(string(text)) {
	case "include":
		*a = HTTPParsingActionInclude
	case "exclude":
		*a = HTTPParsingActionExclude
	case "obfuscate":
		*a = HTTPParsingActionObfuscate
	default:
		return fmt.Errorf("invalid parsing action: %q (valid: include, exclude, obfuscate)", string(text))
	}
	return nil
}

func (a HTTPParsingAction) MarshalText() ([]byte, error) {
	switch a {
	case HTTPParsingActionInclude:
		return []byte("include"), nil
	case HTTPParsingActionExclude:
		return []byte("exclude"), nil
	case HTTPParsingActionObfuscate:
		return []byte("obfuscate"), nil
	default:
		return nil, fmt.Errorf("unknown parsing action: %d", a)
	}
}

func (HTTPParsingAction) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"include", "exclude", "obfuscate"},
	}
}

// HTTPParsingScope represents the scope of a parsing rule.
type HTTPParsingScope uint8

const (
	HTTPParsingScopeRequest HTTPParsingScope = iota + 1
	HTTPParsingScopeResponse
	HTTPParsingScopeAll
)

func (a *HTTPParsingScope) UnmarshalText(text []byte) error {
	switch strings.TrimSpace(string(text)) {
	case "request":
		*a = HTTPParsingScopeRequest
	case "response":
		*a = HTTPParsingScopeResponse
	case "all":
		*a = HTTPParsingScopeAll
	default:
		return fmt.Errorf("invalid parsing scope: %q (valid: request, response, all)", string(text))
	}
	return nil
}

func (a HTTPParsingScope) MarshalText() ([]byte, error) {
	switch a {
	case HTTPParsingScopeRequest:
		return []byte("request"), nil
	case HTTPParsingScopeResponse:
		return []byte("response"), nil
	case HTTPParsingScopeAll:
		return []byte("all"), nil
	default:
		return nil, fmt.Errorf("unknown parsing scope: %d", a)
	}
}

func (HTTPParsingScope) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"request", "response", "all"},
	}
}

// HTTPParsingMatchOrder controls how rules are evaluated.
type HTTPParsingMatchOrder uint8

const (
	HTTPParsingMatchOrderFirstMatchWins HTTPParsingMatchOrder = iota + 1
)

func (m *HTTPParsingMatchOrder) UnmarshalText(text []byte) error {
	switch strings.TrimSpace(string(text)) {
	case "first_match_wins":
		*m = HTTPParsingMatchOrderFirstMatchWins
	default:
		return fmt.Errorf("invalid parsing match order: %q (valid: first_match_wins)", string(text))
	}
	return nil
}

func (m HTTPParsingMatchOrder) MarshalText() ([]byte, error) {
	switch m {
	case HTTPParsingMatchOrderFirstMatchWins:
		return []byte("first_match_wins"), nil
	default:
		return nil, fmt.Errorf("unknown parsing match order: %d", m)
	}
}

func (HTTPParsingMatchOrder) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"first_match_wins"},
	}
}

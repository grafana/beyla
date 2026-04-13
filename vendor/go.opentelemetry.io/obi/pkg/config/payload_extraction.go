// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config // import "go.opentelemetry.io/obi/pkg/config"

import (
	"fmt"
	"strings"

	"github.com/invopop/jsonschema"
	"github.com/ohler55/ojg/jp"
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
		p.HTTP.GenAI.Enabled() ||
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
	// GenAI payload extraction
	GenAI GenAIConfig `yaml:"genai"`
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

type GenAIConfig struct {
	// OpenAI payload extraction and parsing
	OpenAI OpenAIConfig `yaml:"openai"`
	// Anthropic payload extraction and parsing
	Anthropic AnthropicConfig `yaml:"anthropic"`
}

func (g *GenAIConfig) Enabled() bool {
	return g.Anthropic.Enabled || g.OpenAI.Enabled
}

type OpenAIConfig struct {
	// Enable OpenAI payload extraction and parsing
	Enabled bool `yaml:"enabled" env:"OTEL_EBPF_HTTP_OPENAI_ENABLED" validate:"boolean"`
}

type AnthropicConfig struct {
	// Enable Anthropic payload extraction and parsing
	Enabled bool `yaml:"enabled" env:"OTEL_EBPF_HTTP_ANTHROPIC_ENABLED" validate:"boolean"`
}

// EnrichmentConfig configures HTTP header and payload extraction with policy-based rules.
type EnrichmentConfig struct {
	// Enable HTTP header and payload enrichment
	Enabled bool `yaml:"enabled" env:"OTEL_EBPF_HTTP_ENRICHMENT_ENABLED" validate:"boolean"`
	// Policy controls the default behavior
	Policy HTTPParsingPolicy `yaml:"policy"`
	// Rules is an ordered list of include/exclude/obfuscate rules.
	Rules []HTTPParsingRule `yaml:"rules"`
}

// Validate checks the enrichment config for cross-field consistency errors.
// Required fields (action, type, scope) are enforced by validate:"required" tags.
func (c EnrichmentConfig) Validate() error {
	for i, rule := range c.Rules {
		switch rule.Type {
		case HTTPParsingRuleTypeHeaders:
			if err := validateHeaderRule(i, rule); err != nil {
				return err
			}
		case HTTPParsingRuleTypeBody:
			if err := validateBodyRule(i, rule); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateHeaderRule(i int, rule HTTPParsingRule) error {
	if len(rule.Match.ObfuscationJSONPaths) > 0 {
		return fmt.Errorf("rule %d: header rules cannot use obfuscation_json_paths", i)
	}
	if len(rule.Match.Patterns) == 0 {
		return fmt.Errorf("rule %d: header rules require at least one pattern", i)
	}
	return nil
}

func validateBodyRule(i int, rule HTTPParsingRule) error {
	if len(rule.Match.Patterns) > 0 {
		return fmt.Errorf("rule %d: body rules cannot use patterns", i)
	}
	if rule.Match.CaseSensitive {
		return fmt.Errorf("rule %d: body rules cannot use case_sensitive", i)
	}
	if rule.Action == HTTPParsingActionObfuscate && len(rule.Match.ObfuscationJSONPaths) == 0 {
		return fmt.Errorf("rule %d: action \"obfuscate\" on body rule requires obfuscation_json_paths", i)
	}
	if rule.Action != HTTPParsingActionObfuscate && len(rule.Match.ObfuscationJSONPaths) > 0 {
		return fmt.Errorf("rule %d: obfuscation_json_paths can only be used with action \"obfuscate\"", i)
	}
	return nil
}

// HTTPParsingPolicy defines the default action for http enrichment rules.
type HTTPParsingPolicy struct {
	// DefaultAction specifies what to do when no rule matches, per type.
	DefaultAction HTTPParsingDefaultAction `yaml:"default_action"`
	// ObfuscationString is the replacement string used when a rule's action is "obfuscate"
	ObfuscationString string `yaml:"obfuscation_string" env:"OTEL_EBPF_HTTP_ENRICHMENT_OBFUSCATION_STRING"`
}

// HTTPParsingDefaultAction specifies the default action per rule type.
type HTTPParsingDefaultAction struct {
	Headers HTTPParsingAction `yaml:"headers" validate:"required"`
	Body    HTTPParsingAction `yaml:"body" validate:"required"`
}

// HTTPParsingRule defines a single include/exclude/obfuscate rule for HTTP header and payload extraction.
type HTTPParsingRule struct {
	// Action of the rule: "include", "exclude", or "obfuscate"
	Action HTTPParsingAction `yaml:"action" validate:"required"`
	// Type specifies what this rule matches against: "headers" or "body"
	Type HTTPParsingRuleType `yaml:"type" validate:"required"`
	// Scope of the rule: "request", "response", or "all"
	Scope HTTPParsingScope `yaml:"scope" validate:"required"`
	// Match defines the matching criteria for this rule
	Match HTTPParsingMatch `yaml:"match"`
}

// HTTPParsingRuleType specifies the target of a parsing rule.
type HTTPParsingRuleType uint8

const (
	HTTPParsingRuleTypeHeaders HTTPParsingRuleType = iota + 1
	HTTPParsingRuleTypeBody
)

func (t *HTTPParsingRuleType) UnmarshalText(text []byte) error {
	switch strings.TrimSpace(string(text)) {
	case "headers":
		*t = HTTPParsingRuleTypeHeaders
	case "body":
		*t = HTTPParsingRuleTypeBody
	default:
		return fmt.Errorf("invalid parsing rule type: %q (valid: headers, body)", string(text))
	}
	return nil
}

func (t HTTPParsingRuleType) MarshalText() ([]byte, error) {
	switch t {
	case HTTPParsingRuleTypeHeaders:
		return []byte("headers"), nil
	case HTTPParsingRuleTypeBody:
		return []byte("body"), nil
	default:
		return nil, fmt.Errorf("unknown parsing rule type: %d", t)
	}
}

func (HTTPParsingRuleType) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"headers", "body"},
	}
}

// JSONPathExpr holds a JSONPath expression string and its compiled form.
type JSONPathExpr struct {
	str  string
	expr jp.Expr
}

// NewJSONPathExpr creates a JSONPathExpr from a string, compiling it immediately.
func NewJSONPathExpr(path string) (JSONPathExpr, error) {
	expr, err := jp.ParseString(path)
	if err != nil {
		return JSONPathExpr{}, fmt.Errorf("invalid JSONPath expression %q: %w", path, err)
	}
	return JSONPathExpr{str: path, expr: expr}, nil
}

func (j *JSONPathExpr) UnmarshalText(text []byte) error {
	expr, err := jp.ParseString(string(text))
	if err != nil {
		return fmt.Errorf("invalid JSONPath expression %q: %w", string(text), err)
	}
	j.str = string(text)
	j.expr = expr
	return nil
}

func (j JSONPathExpr) MarshalText() ([]byte, error) {
	return []byte(j.str), nil
}

func (JSONPathExpr) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type:        "string",
		Description: "A JSONPath expression string.",
		Examples:    []any{"$.password", "$.user.name", "$.items[0].id"},
	}
}

// Expr returns the compiled JSONPath expression.
func (j *JSONPathExpr) Expr() jp.Expr {
	return j.expr
}

// String returns the original JSONPath string.
func (j *JSONPathExpr) String() string {
	return j.str
}

// HTTPParsingMatch defines matching criteria for an HTTP parsing rule.
// Header rules use Patterns and CaseSensitive. Body rules use ObfuscationJSONPaths.
// URLPathPatterns and Methods are shared across both types.
type HTTPParsingMatch struct {
	// Patterns is a list of glob patterns to match header names against (headers only)
	Patterns []services.GlobAttr `yaml:"patterns"`
	// CaseSensitive controls whether header matching is case-sensitive (headers only)
	CaseSensitive bool `yaml:"case_sensitive"`
	// ObfuscationJSONPaths is a list of JSONPath expressions for fields to obfuscate (body only)
	ObfuscationJSONPaths []JSONPathExpr `yaml:"obfuscation_json_paths"`
	// URLPathPatterns is a list of glob patterns to match the request path against (shared)
	URLPathPatterns []services.GlobAttr `yaml:"url_path_patterns"`
	// Methods is a list of HTTP methods this rule applies to (shared). Empty means all methods.
	Methods []HTTPMethod `yaml:"methods"`
}

// UnmarshalYAML deserializes the match config and compiles glob patterns
// and JSONPath expressions from their raw string values.
func (m *HTTPParsingMatch) UnmarshalYAML(value *yaml.Node) error {
	var raw struct {
		Patterns             []string     `yaml:"patterns"`
		CaseSensitive        bool         `yaml:"case_sensitive"`
		ObfuscationJSONPaths []string     `yaml:"obfuscation_json_paths"`
		URLPathPatterns      []string     `yaml:"url_path_patterns"`
		Methods              []HTTPMethod `yaml:"methods"`
	}
	if err := value.Decode(&raw); err != nil {
		return err
	}

	m.CaseSensitive = raw.CaseSensitive
	m.Methods = raw.Methods

	// Compile header name patterns
	m.Patterns = make([]services.GlobAttr, 0, len(raw.Patterns))
	for _, pattern := range raw.Patterns {
		compilePattern := pattern
		if !m.CaseSensitive {
			compilePattern = strings.ToLower(pattern)
		}
		m.Patterns = append(m.Patterns, services.NewGlob(compilePattern))
	}

	// Compile route patterns
	m.URLPathPatterns = make([]services.GlobAttr, 0, len(raw.URLPathPatterns))
	for _, pattern := range raw.URLPathPatterns {
		m.URLPathPatterns = append(m.URLPathPatterns, services.NewGlob(pattern))
	}

	// Compile JSONPath expressions
	m.ObfuscationJSONPaths = make([]JSONPathExpr, 0, len(raw.ObfuscationJSONPaths))
	for _, path := range raw.ObfuscationJSONPaths {
		jpExpr, err := NewJSONPathExpr(path)
		if err != nil {
			return err
		}
		m.ObfuscationJSONPaths = append(m.ObfuscationJSONPaths, jpExpr)
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

// HTTPMethod represents a validated HTTP method.
type HTTPMethod string

const (
	HTTPMethodGET     HTTPMethod = "GET"
	HTTPMethodPOST    HTTPMethod = "POST"
	HTTPMethodPUT     HTTPMethod = "PUT"
	HTTPMethodDELETE  HTTPMethod = "DELETE"
	HTTPMethodPATCH   HTTPMethod = "PATCH"
	HTTPMethodHEAD    HTTPMethod = "HEAD"
	HTTPMethodOPTIONS HTTPMethod = "OPTIONS"
)

var validHTTPMethods = map[HTTPMethod]struct{}{
	HTTPMethodGET:     {},
	HTTPMethodPOST:    {},
	HTTPMethodPUT:     {},
	HTTPMethodDELETE:  {},
	HTTPMethodPATCH:   {},
	HTTPMethodHEAD:    {},
	HTTPMethodOPTIONS: {},
}

func (m *HTTPMethod) UnmarshalText(text []byte) error {
	upper := HTTPMethod(strings.ToUpper(strings.TrimSpace(string(text))))
	if _, ok := validHTTPMethods[upper]; !ok {
		return fmt.Errorf("invalid HTTP method: %q (valid: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)", string(text))
	}
	*m = upper
	return nil
}

func (HTTPMethod) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{HTTPMethodGET, HTTPMethodPOST, HTTPMethodPUT, HTTPMethodDELETE, HTTPMethodPATCH, HTTPMethodHEAD, HTTPMethodOPTIONS},
	}
}

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config // import "go.opentelemetry.io/obi/pkg/config"

type PayloadExtraction struct {
	HTTP HTTPConfig `yaml:"http"`
}

func (p PayloadExtraction) Enabled() bool {
	return p.HTTP.GraphQL.Enabled || p.HTTP.Elasticsearch.Enabled || p.HTTP.AWS.Enabled || p.HTTP.SQLPP.Enabled
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

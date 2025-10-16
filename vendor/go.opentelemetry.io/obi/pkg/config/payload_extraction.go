// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config

type PayloadExtraction struct {
	HTTP HTTPConfig `yaml:"http"`
}

type HTTPConfig struct {
	// GraphQL payload extraction and parsing
	GraphQL GraphQLConfig `yaml:"graphql"`
}

type GraphQLConfig struct {
	// Enable GraphQL payload extraction and parsing
	Enabled bool `yaml:"enabled" env:"OTEL_EBPF_HTTP_GRAPHQL_ENABLED"`
}

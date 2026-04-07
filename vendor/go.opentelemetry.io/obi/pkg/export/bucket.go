// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package export // import "go.opentelemetry.io/obi/pkg/export"

// Buckets defines the histograms bucket boundaries, and allows users to
// redefine them
type Buckets struct {
	DurationHistogram            []float64 `yaml:"duration_histogram"`
	RequestSizeHistogram         []float64 `yaml:"request_size_histogram"`
	ResponseSizeHistogram        []float64 `yaml:"response_size_histogram"`
	GenAITokenUsageHistogram     []float64 `yaml:"gen_ai_client_token_usage_histogram"`
	GenAIClientDurationHistogram []float64 `yaml:"gen_ai_client_operation_duration_histogram"`
}

var DefaultBuckets = Buckets{
	// Default values as specified in the OTEL specification
	// https://opentelemetry.io/docs/specs/semconv/http/http-metrics/#metric-httpserverrequestduration
	DurationHistogram: []float64{0, 0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10},

	RequestSizeHistogram:  []float64{0, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192},
	ResponseSizeHistogram: []float64{0, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192},

	// https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-metrics/#metric-gen_aiclienttokenusage
	GenAITokenUsageHistogram: []float64{1, 4, 16, 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216, 67108864},
	// https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-metrics/#metric-gen_aiclientoperationduration
	GenAIClientDurationHistogram: []float64{0.01, 0.02, 0.04, 0.08, 0.16, 0.32, 0.64, 1.28, 2.56, 5.12, 10.24, 20.48, 40.96, 81.92},
}

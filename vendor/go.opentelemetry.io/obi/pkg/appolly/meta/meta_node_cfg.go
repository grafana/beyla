// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meta // import "go.opentelemetry.io/obi/pkg/appolly/meta"

import "time"

// RetryConfig holds the retry policy for metadata fetch operations.
// It controls the exponential backoff used in physical node, cloud instance or local virtual machine.
type RetryConfig struct {
	// Timeout specifies the maximum total time allowed for all retry attempts before giving up.
	Timeout time.Duration `yaml:"timeout" env:"OTEL_EBPF_METADATA_RETRY_TIMEOUT" validate:"gte=0"`
	// StartInterval specifies the initial wait duration between the first and second retry attempt.
	StartInterval time.Duration `yaml:"start_interval" env:"OTEL_EBPF_METADATA_RETRY_START_INTERVAL" validate:"gte=0"`
	// MaxInterval specifies the upper bound on the wait duration between consecutive retry attempts.
	MaxInterval time.Duration `yaml:"max_interval" env:"OTEL_EBPF_METADATA_RETRY_MAX_INTERVAL" validate:"gte=0"`
}

var DefaultRetryConfig = RetryConfig{
	Timeout:       30 * time.Second,
	StartInterval: 500 * time.Millisecond,
	MaxInterval:   5 * time.Second,
}

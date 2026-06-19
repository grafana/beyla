// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package imetrics // import "go.opentelemetry.io/obi/pkg/export/imetrics"

// AvoidedServicesConfig controls the avoided-services internal metric.
type AvoidedServicesConfig struct {
	// Disabled disables the avoided-services internal metric.
	Disabled bool `yaml:"disabled" env:"OTEL_EBPF_INTERNAL_METRICS_AVOIDED_SERVICES_DISABLED"`
	// Limit bounds the number of avoided-services metric series, including the overflow series.
	// 0 uses the OpenTelemetry default metric cardinality limit.
	Limit int `yaml:"limit" env:"OTEL_EBPF_INTERNAL_METRICS_AVOIDED_SERVICES_LIMIT" validate:"gte=0"`
}

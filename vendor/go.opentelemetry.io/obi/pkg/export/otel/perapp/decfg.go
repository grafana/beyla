// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package perapp is a placeholder for the future global and per-service support
// of different metrics/traces export options.
package perapp // import "go.opentelemetry.io/obi/pkg/export/otel/perapp"

import (
	"go.opentelemetry.io/obi/pkg/export"
)

// MetricsConfig is a placeholder for the progressive support of global and per-service
// configuration of metrics.
type MetricsConfig struct {
	// Features of metrics that can be exported. Accepted values: application, network,
	// application_span, application_service_graph, ...
	// envDefault is provided to avoid breaking changes
	Features export.Features `yaml:"features" env:"OTEL_EBPF_METRICS_FEATURES,expand" envDefault:"${OTEL_EBPF_METRIC_FEATURES}" envSeparator:","`
}

// SvcMetricsConfig is equivalent to MetricsConfig, but avoids defining environment variable, since this
// is a per-service configuration that needs to be defined exclusively in the service definition YAML.
type SvcMetricsConfig struct {
	// Features of metrics that can be exported. Accepted values: application, network,
	// application_span, application_service_graph, ...
	// envDefault is provided to avoid breaking changes
	Features export.Features `yaml:"features"`
}

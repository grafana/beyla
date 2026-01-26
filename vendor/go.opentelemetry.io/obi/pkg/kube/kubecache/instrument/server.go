// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package instrument

import (
	"context"

	"go.opentelemetry.io/obi/pkg/export/connector"
)

const defaultMetricsPath = "/metrics"

type InternalMetricsConfig struct {
	Port int    `yaml:"port,omitempty" env:"OTEL_EBPF_K8S_CACHE_INTERNAL_METRICS_PROMETHEUS_PORT"`
	Path string `yaml:"path,omitempty" env:"OTEL_EBPF_K8S_CACHE_INTERNAL_METRICS_PROMETHEUS_PATH"`
}

type contextKey struct{}

// Start in background an internal metrics handler and return a context containing it.
// The metrics handler can be later retrieved via FromContext function.
func Start(ctx context.Context, cfg *InternalMetricsConfig) context.Context {
	if cfg == nil || cfg.Port == 0 {
		return ctx
	}
	if cfg.Path == "" {
		cfg.Path = defaultMetricsPath
	}
	promMgr := connector.PrometheusManager{}
	metrics := prometheusInternalMetrics(cfg, &promMgr)
	promMgr.StartHTTP(ctx)
	return context.WithValue(ctx, contextKey{}, InternalMetrics(metrics))
}

// FromContext returns the internal metrics handler from the context. If any.
// If no metrics handler has been defined, it will return a NOOP metrics handler.
func FromContext(ctx context.Context) InternalMetrics {
	metrics := ctx.Value(contextKey{})
	if metrics == nil {
		return &noopMetrics{}
	}
	return metrics.(InternalMetrics)
}

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package avoidedsvc // import "go.opentelemetry.io/obi/pkg/internal/avoidedsvc"

import "sync"

const (
	// DefaultLimit follows the OpenTelemetry metric cardinality limit default.
	DefaultLimit = 2000
	// OverflowAttribute is the OpenTelemetry metric overflow attribute.
	OverflowAttribute = "otel.metric.overflow"
	// PrometheusOverflowLabel is the Prometheus-safe form of OverflowAttribute.
	PrometheusOverflowLabel = "otel_metric_overflow"
	prometheusOverflowTrue  = "true"
	prometheusOverflowFalse = "false"
)

// Labels contains the bounded label values for one avoided-services metric point.
type Labels struct {
	ServiceName      string
	ServiceNamespace string
	TelemetryType    string
	Overflow         bool
}

// PrometheusValues returns values ordered for the Prometheus avoided-services GaugeVec.
func (l Labels) PrometheusValues() []string {
	if l.Overflow {
		return []string{"", "", "", prometheusOverflowTrue}
	}

	return []string{
		l.ServiceName,
		l.ServiceNamespace,
		l.TelemetryType,
		prometheusOverflowFalse,
	}
}

type identity struct {
	serviceName      string
	serviceNamespace string
	telemetryType    string
}

type Limiter struct {
	limit int
	seen  map[identity]struct{}
	mux   sync.Mutex
}

// NewLimiter creates a limiter that bounds avoided-services metric series.
func NewLimiter(limit int) *Limiter {
	return &Limiter{
		limit: LimitOrDefault(limit),
		seen:  map[identity]struct{}{},
	}
}

// LimitOrDefault returns the configured limit or the OpenTelemetry default.
func LimitOrDefault(limit int) int {
	if limit <= 0 {
		return DefaultLimit
	}
	return limit
}

// Labels returns either the original labels or the OpenTelemetry overflow label set.
func (l *Limiter) Labels(serviceName, serviceNamespace, _ string, telemetryType string) Labels {
	labels := Labels{
		ServiceName:      serviceName,
		ServiceNamespace: serviceNamespace,
		TelemetryType:    telemetryType,
	}
	if l == nil {
		return labels
	}

	id := identity{
		serviceName:      serviceName,
		serviceNamespace: serviceNamespace,
		telemetryType:    telemetryType,
	}

	l.mux.Lock()
	defer l.mux.Unlock()
	if _, ok := l.seen[id]; ok {
		return labels
	}
	if len(l.seen) >= l.limit-1 {
		return Labels{Overflow: true}
	}

	l.seen[id] = struct{}{}
	return labels
}

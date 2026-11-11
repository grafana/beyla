// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"context"

	"go.opentelemetry.io/otel/sdk/instrumentation"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
)

// Use a producer so detaching releases both metadata and cumulative/delta state;
// a synchronous SDK counter retains the removed series in its aggregation.
type dynamicInvocationProducer struct {
	imetrics.DynamicProbeCounters
	name        attributes.Name
	temporality metricdata.Temporality
}

func (p *dynamicInvocationProducer) Produce(ctx context.Context) ([]metricdata.ScopeMetrics, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	samples := p.CollectDynamicProbes(p.temporality == metricdata.DeltaTemporality)
	if len(samples) == 0 {
		return nil, nil
	}
	points := make([]metricdata.DataPoint[int64], 0, len(samples))
	for _, sample := range samples {
		points = append(points, metricdata.DataPoint[int64]{Attributes: sample.Attributes, StartTime: sample.StartTime, Time: sample.Time, Value: int64(sample.Count)})
	}
	return []metricdata.ScopeMetrics{{
		Scope: instrumentation.Scope{Name: internalMetricsMeterName},
		Metrics: []metricdata.Metrics{{Name: p.name.OTEL, Unit: p.name.Unit, Description: imetrics.DynamicInvocationDescription,
			Data: metricdata.Sum[int64]{DataPoints: points, Temporality: p.temporality, IsMonotonic: true},
		}},
	}}, nil
}

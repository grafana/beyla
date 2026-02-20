// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/expire"
	"go.opentelemetry.io/obi/pkg/export/otel/metric/api/metric"
)

var timeNow = time.Now

func plog() *slog.Logger {
	return slog.With("component", "otel.Expirer")
}

type removableMetric[VT any] interface {
	Remove(context.Context, ...metric.RemoveOption)
}

// Expirer drops metrics from labels that haven't been updated during a given timeout.
// It has multiple generic types to allow it working with different dataPoints (FloatVal, IntCounter...)
// and different types of data (int, float...).
// Record: type of the record that holds the metric data request.Span, ebpf.Record, process.Status...
// Metric: type of the dataPoint kind: IntCounter, FloatVal...
// VT: type of the value inside the datapoint: int, float64...
type Expirer[Record any, Metric removableMetric[ValType], ValType any] struct {
	ctx     context.Context
	attrs   []attributes.Field[Record, attribute.KeyValue]
	metric  Metric
	entries *expire.ExpiryMap[attribute.Set]
	log     *slog.Logger

	clock          expire.Clock
	lastExpiration time.Time
	ttl            time.Duration
}

// NewExpirer creates an expirer that wraps data points of a given type. Its labeled instances are dropped
// if they haven't been updated during the last timeout period.
// Arguments:
// - instancer: the constructor of each datapoint object (e.g. NewIntCounter, NewFloatVal...)
// - attrs: attributes for that given data point
// - clock: function that provides the current time
// - ttl: time to live of the datapoints whose attribute sets haven't been updated
func NewExpirer[Record any, Metric removableMetric[ValType], ValType any](
	ctx context.Context,
	metric Metric,
	attrs []attributes.Field[Record, attribute.KeyValue],
	clock expire.Clock,
	ttl time.Duration,
) *Expirer[Record, Metric, ValType] {
	exp := Expirer[Record, Metric, ValType]{
		ctx:            ctx,
		metric:         metric,
		attrs:          attrs,
		entries:        expire.NewExpiryMap[attribute.Set](clock, ttl),
		log:            plog().With("type", fmt.Sprintf("%T", metric)),
		clock:          clock,
		lastExpiration: clock(),
		ttl:            ttl,
	}
	return &exp
}

// ForRecord returns the data point for the given eBPF record. If that record
// is accessed for the first time, a new data point is created.
// If not, a cached copy is returned and the "last access" cache time is updated.
// Extra attributes can be explicitly added (e.g. cpu_mode="wait")
func (ex *Expirer[Record, Metric, ValType]) ForRecord(r Record, extraAttrs ...attribute.KeyValue) (Metric, attribute.Set) {
	// to save resources, metrics expiration is triggered each TTL. This means that an expired
	// metric might stay visible after 2*TTL time after not being updated
	now := ex.clock()
	if now.Sub(ex.lastExpiration) >= ex.ttl {
		ex.removeOutdated(ex.ctx)
		ex.lastExpiration = now
	}
	recordAttrs, attrValues := ex.recordAttributes(r, extraAttrs...)
	return ex.metric, ex.entries.GetOrCreate(attrValues, func() attribute.Set {
		ex.log.Debug("storing new metric label set", "labelValues", attrValues)
		return recordAttrs
	})
}

func (ex *Expirer[Record, Metric, ValType]) recordAttributes(m Record, extraAttrs ...attribute.KeyValue) (attribute.Set, []string) {
	keyVals := make([]attribute.KeyValue, 0, len(ex.attrs)+len(extraAttrs))
	vals := make([]string, 0, len(ex.attrs)+len(extraAttrs))

	for _, attr := range ex.attrs {
		kv := attr.Get(m)
		keyVals = append(keyVals, kv)
		vals = append(vals, kv.Value.Emit())
	}
	keyVals = append(keyVals, extraAttrs...)
	for i := range extraAttrs {
		vals = append(vals, extraAttrs[i].Value.Emit())
	}

	return attribute.NewSet(keyVals...), vals
}

func (ex *Expirer[Record, Metric, ValType]) removeOutdated(ctx context.Context) {
	for _, attrs := range ex.entries.DeleteExpired() {
		ex.deleteMetricInstance(ctx, attrs)
	}
}

func (ex *Expirer[Record, Metric, ValType]) deleteMetricInstance(ctx context.Context, attrs attribute.Set) {
	if ex.log.Enabled(ex.ctx, slog.LevelDebug) {
		ex.logger(attrs).Debug("deleting old OTEL metric")
	}
	ex.metric.Remove(ctx, metric.WithAttributeSet(attrs))
}

func (ex *Expirer[Record, Metric, ValType]) logger(attrs attribute.Set) *slog.Logger {
	fmtAttrs := make([]any, 0, attrs.Len()*2)
	for it := attrs.Iter(); it.Next(); {
		a := it.Attribute()
		fmtAttrs = append(fmtAttrs, string(a.Key), a.Value.Emit())
	}
	return ex.log.With(fmtAttrs...)
}

// RemoveAllMetrics is explicitly invoked when the metrics reporter of a given service
// instance needs to be shut down
func (ex *Expirer[Record, Metric, ValType]) RemoveAllMetrics(ctx context.Context) {
	for _, attrs := range ex.entries.DeleteAll() {
		ex.deleteMetricInstance(ctx, attrs)
	}
}

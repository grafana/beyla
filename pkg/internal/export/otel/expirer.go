package otel

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/grafana/beyla/pkg/internal/export/attributes"
	"github.com/grafana/beyla/pkg/internal/export/expire"
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
	entries *expire.ExpiryMap[*expiryMapEntry[Metric, ValType]]
	log     *slog.Logger

	clock          expire.Clock
	lastExpiration time.Time
	ttl            time.Duration
}

type expiryMapEntry[Metric removableMetric[ValType], ValType any] struct {
	metric     Metric
	attributes attribute.Set
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
		entries:        expire.NewExpiryMap[*expiryMapEntry[Metric, ValType]](clock, ttl),
		log:            plog().With("type", fmt.Sprintf("%T", metric)),
		clock:          clock,
		lastExpiration: clock(),
		ttl:            ttl,
	}
	return &exp
}

// ForRecord returns the data point for the given eBPF record. If that record
// s accessed for the first time, a new data point is created.
// If not, a cached copy is returned and the "last access" cache time is updated.
// Extra attributes can be explicitly added (e.g. process_cpu_state="wait")
func (ex *Expirer[Record, Metric, ValType]) ForRecord(r Record, extraAttrs ...attribute.KeyValue) (Metric, attribute.Set) {
	// to save resources, metrics expiration is triggered each TTL. This means that an expired
	// metric might stay visible after 2*TTL time after not being updated
	now := ex.clock()
	if now.Sub(ex.lastExpiration) >= ex.ttl {
		ex.removeOutdated(ex.ctx)
		ex.lastExpiration = now
	}
	recordAttrs, attrValues := ex.recordAttributes(r, extraAttrs...)
	return ex.entries.GetOrCreate(attrValues, func() *expiryMapEntry[Metric, ValType] {
		ex.log.With("labelValues", attrValues).Debug("storing new metric label set")
		return &expiryMapEntry[Metric, ValType]{
			metric:     ex.metric,
			attributes: recordAttrs,
		}
	}).metric, recordAttrs
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
	if old := ex.entries.DeleteExpired(); len(old) > 0 {
		for _, om := range old {
			ex.log.Debug("deleting old OTEL metric", "labelValues", om)
			om.metric.Remove(ctx, metric.WithAttributeSet(om.attributes))
		}
	}
}

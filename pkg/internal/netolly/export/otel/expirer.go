package otel

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sync/atomic"
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

type loader[T any] interface {
	Load() T
	Attributes() attribute.Set
	SetAttributes(attribute.Set)
}

type observer[T any] interface {
	Observe(T, ...metric.ObserveOption)
}

// Expirer drops metrics from labels that haven't been updated during a given timeout
// Record: type of the record that holds the metric data request.Span, ebpf.Record, process.Status...
// Metric: type of the metric kind: Counter, Gauge...
// VT: type of the metric value: int, float...
type Expirer[Record any, OT observer[VT], Metric loader[VT], VT any] struct {
	instancer func(set attribute.Set) Metric
	attrs     []attributes.Field[Record, attribute.KeyValue]
	entries   *expire.ExpiryMap[Metric]
	log       *slog.Logger
}

type metricAttributes struct {
	attributes attribute.Set
}

func (g *metricAttributes) Attributes() attribute.Set {
	return g.attributes
}

func (g *metricAttributes) SetAttributes(a attribute.Set) {
	g.attributes = a
}

type Counter struct {
	metricAttributes
	val atomic.Int64
}

func NewCounter(attributes attribute.Set) *Counter {
	return &Counter{metricAttributes: metricAttributes{attributes: attributes}}
}
func (g *Counter) Load() int64 {
	return g.val.Load()
}

func (g *Counter) Add(v int64) {
	g.val.Add(v)
}

type Gauge struct {
	metricAttributes
	// Go standard library does not provide atomic packages so we need to
	// store the float as bytes and then convert it with the math package
	floatBits uint64
}

func NewGauge(attributes attribute.Set) *Gauge {
	return &Gauge{metricAttributes: metricAttributes{attributes: attributes}}
}

func (g *Gauge) Load() float64 {
	return math.Float64frombits(atomic.LoadUint64(&g.floatBits))
}

func (g *Gauge) Set(val float64) {
	atomic.StoreUint64(&g.floatBits, math.Float64bits(val))
}

// NewExpirer creates a metric that wraps a Counter. Its labeled instances are dropped
// if they haven't been updated during the last timeout period
func NewExpirer[Record any, OT observer[VT], Metric loader[VT], VT any](
	instancer func(set attribute.Set) Metric,
	attrs []attributes.Field[Record, attribute.KeyValue],
	clock expire.Clock,
	expireTime time.Duration,
) *Expirer[Record, OT, Metric, VT] {
	exp := Expirer[Record, OT, Metric, VT]{
		instancer: instancer,
		attrs:     attrs,
		entries:   expire.NewExpiryMap[Metric](clock, expireTime),
	}
	exp.log = plog().With("type", fmt.Sprintf("%T", exp))
	return &exp
}

// ForRecord returns the Counter for the given eBPF record. If that record
// s accessed for the first time, a new Counter is created.
// If not, a cached copy is returned and the "last access" cache time is updated.
func (ex *Expirer[Record, OT, Metric, VT]) ForRecord(r Record) Metric {
	recordAttrs, attrValues := ex.recordAttributes(r)
	return ex.entries.GetOrCreate(attrValues, func() Metric {
		ex.log.With("labelValues", attrValues).Debug("storing new metric label set")
		return ex.instancer(recordAttrs)
	})
}

func (ex *Expirer[Record, OT, Metric, VT]) Collect(_ context.Context, observer OT) error {
	//ex.log.Debug("invoking metrics collection")
	if old := ex.entries.DeleteExpired(); len(old) > 0 {
		ex.log.With("labelValues", old).Debug("deleting old OTEL metric")
	}

	for _, v := range ex.entries.All() {
		observer.Observe(v.Load(), metric.WithAttributeSet(v.Attributes()))
	}

	return nil
}

func (ex *Expirer[Record, OT, Metric, VT]) recordAttributes(m Record) (attribute.Set, []string) {
	keyVals := make([]attribute.KeyValue, 0, len(ex.attrs))
	vals := make([]string, 0, len(ex.attrs))

	for _, attr := range ex.attrs {
		kv := attr.Get(m)
		keyVals = append(keyVals, kv)
		vals = append(vals, kv.Value.Emit())
	}

	return attribute.NewSet(keyVals...), vals
}

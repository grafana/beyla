package otel

import (
	"context"
	"fmt"
	"log/slog"
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
	attrs     []attributes.Field[Record, string]
	entries   *expire.ExpiryMap[Metric]
	log       *slog.Logger
}

type Counter struct {
	attributes attribute.Set
	val        atomic.Int64
}

func NewCounter(attributes attribute.Set) *Counter {
	return &Counter{attributes: attributes}
}
func (g *Counter) Load() int64 {
	return g.val.Load()
}

func (g *Counter) Attributes() attribute.Set {
	return g.attributes
}

func (g *Counter) SetAttributes(a attribute.Set) {
	g.attributes = a
}

type Gauge struct {
	attributes attribute.Set
	val        atomic.Value
}

func NewGauge(attributes attribute.Set, initVal float64) *Gauge {
	val := atomic.Value{}
	val.Store(initVal)
	return &Gauge{attributes: attributes, val: val}
}

func (g Gauge) Load() float64 {
	return g.val.Load().(float64)
}

func (g Gauge) Set(val float64) {
	g.val.Store(val)
}

// NewExpirer creates a metric that wraps a Counter. Its labeled instances are dropped
// if they haven't been updated during the last timeout period
func NewExpirer[Record any, OT observer[VT], Metric loader[VT], VT any](
	instancer func(set attribute.Set) Metric,
	attrs []attributes.Field[Record, string],
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
	ex.log.Debug("invoking metrics collection")
	old := ex.entries.DeleteExpired()
	ex.log.With("labelValues", old).Debug("deleting old OTEL metric")

	for _, v := range ex.entries.All() {
		observer.Observe(v.Load(), metric.WithAttributeSet(v.Attributes()))
	}

	return nil
}

func (ex *Expirer[Record, OT, Metric, VT]) recordAttributes(m Record) (attribute.Set, []string) {
	keyVals := make([]attribute.KeyValue, 0, len(ex.attrs))
	vals := make([]string, 0, len(ex.attrs))

	for _, attr := range ex.attrs {
		val := attr.Get(m)
		keyVals = append(keyVals, attribute.String(attr.ExposedName, val))
		vals = append(vals, val)
	}

	return attribute.NewSet(keyVals...), vals
}

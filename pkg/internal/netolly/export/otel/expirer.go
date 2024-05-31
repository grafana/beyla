package otel

import (
	"context"
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

type attribGetter interface {
	Attributes() attribute.Set
}

// Expirer drops metrics from labels that haven't been updated during a given timeout
// TODO: generify and move to a common section for using it also in AppO11y, supporting more OTEL metrics
type Expirer[RT attribGetter] struct {
	attrs    []attributes.Field[RT, string]
	counters *expire.ExpiryMap[*Counter]
	gauges *expire.ExpiryMap[*Gauge]
}

type Counter struct {
	attributes attribute.Set
	val        atomic.Int64
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

func (g *Gauge) Load() float64 {
	return g.val.Load().(float64)
}

func (g *Gauge) Set(val float64) {
	g.val.Store(val)
}

// NewExpirer creates a metric that wraps a Counter. Its labeled instances are dropped
// if they haven't been updated during the last timeout period
func NewExpirer[RT attribGetter](attrs []attributes.Field[RT, string], clock expire.Clock, expireTime time.Duration) *Expirer[RT] {
	return &Expirer[RT]{
		attrs:    attrs,
		counters: expire.NewExpiryMap[*Counter](clock, expireTime),
		gauges: expire.NewExpiryMap[*Gauge](clock, expireTime),
	}
}

// CounterForRecord returns the Counter for the given eBPF record. If that record
// s accessed for the first time, a new Counter is created.
// If not, a cached copy is returned and the "last access" cache time is updated.
func (ex *Expirer[RT]) CounterForRecord(m RT) *Counter {
	recordAttrs, attrValues := ex.recordAttributes(m)
	return ex.counters.GetOrCreate(attrValues, func() *Counter {
		plog().With("labelValues", attrValues).Debug("storing new metric label set")
		return &Counter{
			attributes: recordAttrs,
		}
	})
}

func (ex *Expirer[RT]) GaugeForRecord(m RT) *Gauge {
	recordAttrs, attrValues := ex.recordAttributes(m)
	return ex.
}



type observer[VT any] interface {
	Observe(value VT, options ...metric.ObserveOption)
}

func (ex *Expirer[RT]) Collect(_ context.Context, observer observer[]) error {
	log := plog()
	log.Debug("invoking metrics collection")
	if old := ex.counters.DeleteExpired(); len(old) > 0 {
		log.With("labelValues", old).Debug("deleting old OTEL counter")
	}
	if old := ex.gauges.DeleteExpired(); len(old) > 0 {
		log.With("labelValues", old).Debug("deleting old OTEL gauges")
	}

	for _, v := range ex.counters.All() {
		observer.Observe(v.val.Load(), metric.WithAttributeSet(v.attributes))
	}
	for _, v := range ex.gauges.All() {
		observer.Observe(v.val.Load(), metric.WithAttributeSet(v.attributes))
	}

	return nil
}

func (ex *Expirer[RT]) recordAttributes(m RT) (attribute.Set, []string) {
	keyVals := make([]attribute.KeyValue, 0, len(ex.attrs))
	vals := make([]string, 0, len(ex.attrs))

	for _, attr := range ex.attrs {
		val := attr.Get(m)
		keyVals = append(keyVals, attribute.String(attr.ExposedName, val))
		vals = append(vals, val)
	}

	return attribute.NewSet(keyVals...), vals
}

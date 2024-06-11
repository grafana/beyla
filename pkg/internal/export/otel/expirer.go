package otel

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sync"
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

// dataPoint implements a metric value of a given type,
// for a set of attributes
// Example of implementers: FloatVal and IntCounter
type dataPoint[T any] interface {
	// Load the current value for a given set of attributes
	Load() T
	// Attributes return the attributes of the current dataPoint
	Attributes() attribute.Set
}

// observer records measurements for a given metric type
type observer[T any] interface {
	Observe(T, ...metric.ObserveOption)
}

// Expirer drops metrics from labels that haven't been updated during a given timeout.
// It has multiple generic types to allow it working with different dataPoints (FloatVal, IntCounter...)
// and different types of data (int, float...).
// Record: type of the record that holds the metric data request.Span, ebpf.Record, process.Status...
// Metric: type of the dataPoint kind: IntCounter, FloatVal...
// VT: type of the value inside the datapoint: int, float64...
type Expirer[Record any, OT observer[VT], Metric dataPoint[VT], VT any] struct {
	instancer func(set attribute.Set) Metric
	attrs     []attributes.Field[Record, attribute.KeyValue]
	entries   *expire.ExpiryMap[Metric]
	log       *slog.Logger
}

// NewExpirer creates an expirer that wraps data points of a given type. Its labeled instances are dropped
// if they haven't been updated during the last timeout period.
// Arguments:
// - instancer: the constructor of each datapoint object (e.g. NewIntCounter, NewFloatVal...)
// - attrs: attributes for that given data point
// - clock: function that provides the current time
// - ttl: time to live of the datapoints whose attribute sets haven't been updated
func NewExpirer[Record any, OT observer[VT], Metric dataPoint[VT], VT any](
	instancer func(set attribute.Set) Metric,
	attrs []attributes.Field[Record, attribute.KeyValue],
	clock expire.Clock,
	ttl time.Duration,
) *Expirer[Record, OT, Metric, VT] {
	exp := Expirer[Record, OT, Metric, VT]{
		instancer: instancer,
		attrs:     attrs,
		entries:   expire.NewExpiryMap[Metric](clock, ttl),
	}
	exp.log = plog().With("type", fmt.Sprintf("%T", exp))
	return &exp
}

// ForRecord returns the data point for the given eBPF record. If that record
// s accessed for the first time, a new data point is created.
// If not, a cached copy is returned and the "last access" cache time is updated.
// Extra attributes can be explicitly added (e.g. process_cpu_state="wait")
func (ex *Expirer[Record, OT, Metric, VT]) ForRecord(r Record, extraAttrs ...attribute.KeyValue) Metric {
	recordAttrs, attrValues := ex.recordAttributes(r, extraAttrs...)
	return ex.entries.GetOrCreate(attrValues, func() Metric {
		ex.log.With("labelValues", attrValues).Debug("storing new metric label set")
		return ex.instancer(recordAttrs)
	})
}

func (ex *Expirer[Record, OT, Metric, VT]) Collect(_ context.Context, observer OT) error {
	if old := ex.entries.DeleteExpired(); len(old) > 0 {
		ex.log.With("labelValues", old).Debug("deleting old OTEL metric")
	}

	for _, v := range ex.entries.All() {
		observer.Observe(v.Load(), metric.WithAttributeSet(v.Attributes()))
	}

	return nil
}

func (ex *Expirer[Record, OT, Metric, VT]) recordAttributes(m Record, extraAttrs ...attribute.KeyValue) (attribute.Set, []string) {
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

type metricAttributes struct {
	attributes attribute.Set
}

func (g *metricAttributes) Attributes() attribute.Set {
	return g.attributes
}

// IntCounter data point type
type IntCounter struct {
	metricAttributes
	val atomic.Int64
}

func NewIntCounter(attributes attribute.Set) *IntCounter {
	return &IntCounter{metricAttributes: metricAttributes{attributes: attributes}}
}
func (g *IntCounter) Load() int64 {
	return g.val.Load()
}

func (g *IntCounter) Add(v int64) {
	g.val.Add(v)
}

// FloatCounter is a Counter metric for float64 values
type FloatCounter struct {
	metricAttributes
	mt  sync.RWMutex
	val float64
}

func NewFloatCounter(attributes attribute.Set) *FloatCounter {
	return &FloatCounter{metricAttributes: metricAttributes{attributes: attributes}}
}

func (g *FloatCounter) Load() float64 {
	g.mt.RLock()
	defer g.mt.RUnlock()
	return g.val
}

func (g *FloatCounter) Add(v float64) {
	g.mt.Lock()
	defer g.mt.Unlock()
	g.val += v
}

// Gauge data point type
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

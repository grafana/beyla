package prom

import (
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/expire"
)

func plog() *slog.Logger {
	return slog.With("component", "prom.Expirer")
}

// Expirer drops metrics from labels that haven't been updated during a given timeout
type Expirer[T prometheus.Metric] struct {
	entries *expire.ExpiryMap[*MetricEntry[T]]
	wrapped *prometheus.MetricVec
}

type MetricEntry[T prometheus.Metric] struct {
	Metric    T
	LabelVals []string
}

// NewExpirer creates a metric that wraps a given CounterVec. Its labeled instances are dropped
// if they haven't been updated during the last timeout period
func NewExpirer[T prometheus.Metric](wrapped *prometheus.MetricVec, clock func() time.Time, expireTime time.Duration) *Expirer[T] {
	return &Expirer[T]{
		wrapped: wrapped,
		entries: expire.NewExpiryMap[*MetricEntry[T]](clock, expireTime),
	}
}

// WithLabelValues returns the Counter for the given slice of label
// values (same order as the variable labels in Desc). If that combination of
// label values is accessed for the first time, a new Counter is created.
// If not, a cached copy is returned and the "last access" cache time is updated.
func (ex *Expirer[T]) WithLabelValues(lbls ...string) *MetricEntry[T] {
	return ex.entries.GetOrCreate(lbls, func() *MetricEntry[T] {
		plog().With("labelValues", lbls).Debug("storing new metric label set")
		c, err := ex.wrapped.GetMetricWithLabelValues(lbls...)
		// same behavior as specific WithLabelValues implementations
		// no need to return the error
		if err != nil {
			panic(err)
		}
		return &MetricEntry[T]{
			Metric:    c.(T),
			LabelVals: lbls,
		}
	})
}

// Describe wraps prometheus.Collector Describe method
func (ex *Expirer[T]) Describe(descs chan<- *prometheus.Desc) {
	ex.wrapped.Describe(descs)
}

// Collect wraps prometheus.Collector Wrap method
func (ex *Expirer[T]) Collect(metrics chan<- prometheus.Metric) {
	log := plog()
	for _, old := range ex.entries.DeleteExpired() {
		ex.wrapped.DeleteLabelValues(old.LabelVals...)
		log.With("labelValues", old).Debug("deleting old Prometheus metric")
	}
	for _, m := range ex.entries.All() {
		metrics <- m.Metric
	}
}

package expire

import (
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func plog() *slog.Logger {
	return slog.With("component", "prom.Expirer")
}

// Expirer drops metrics from labels that haven't been updated during a given timeout
type Expirer[T prometheus.Metric] struct {
	entries *ExpiryMap[prometheus.Metric]
	wrapped *prometheus.MetricVec
}

// NewExpirer creates a metric that wraps a given CounterVec. Its labeled instances are dropped
// if they haven't been updated during the last timeout period
func NewExpirer[T prometheus.Metric](wrapped *prometheus.MetricVec, clock func() time.Time, expireTime time.Duration) *Expirer[T] {
	return &Expirer[T]{
		wrapped: wrapped,
		entries: NewExpiryMap[prometheus.Metric](clock, expireTime),
	}
}

// WithLabelValues returns the Counter for the given slice of label
// values (same order as the variable labels in Desc). If that combination of
// label values is accessed for the first time, a new Counter is created.
// If not, a cached copy is returned and the "last access" cache time is updated.
func (ex *Expirer[T]) WithLabelValues(lbls ...string) T {
	return ex.entries.GetOrCreate(lbls, func() prometheus.Metric {
		plog().With("labelValues", lbls).Debug("storing new metric label set")
		c, err := ex.wrapped.GetMetricWithLabelValues(lbls...)
		// same behavior as concrete WithLabelValues implementations
		// no need to return the error
		if err != nil {
			panic(err)
		}
		return c
	}).(T)
}

// Describe wraps prometheus.Collector Describe method
func (ex *Expirer[T]) Describe(descs chan<- *prometheus.Desc) {
	ex.wrapped.Describe(descs)
}

// Collect wraps prometheus.Collector Wrap method
func (ex *Expirer[T]) Collect(metrics chan<- prometheus.Metric) {
	log := plog()
	log.Debug("invoking metrics collection")
	for _, old := range ex.entries.DeleteExpired() {
		ex.wrapped.DeleteLabelValues(old...)
		log.With("labelValues", old).Debug("deleting old Prometheus metric")
	}
	for _, m := range ex.entries.All() {
		metrics <- m
	}
}

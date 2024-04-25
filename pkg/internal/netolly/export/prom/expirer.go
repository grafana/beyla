package prom

import (
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/beyla/pkg/internal/netolly/export"
)

var timeNow = time.Now

func plog() *slog.Logger {
	return slog.With("component", "prom.Expirer")
}

// Expirer drops metrics from labels that haven't been updated during a given timeout
type Expirer struct {
	entries *export.ExpiryMap[prometheus.Counter]
	wrapped *prometheus.CounterVec
}

// NewExpirer creates a metric that wraps a given CounterVec. Its labeled instances are dropped
// if they haven't been updated during the last timeout period
func NewExpirer(wrapped *prometheus.CounterVec, expireTime time.Duration) *Expirer {
	return &Expirer{
		wrapped: wrapped,
		entries: export.NewExpiryMap[prometheus.Counter](expireTime, export.WithClock[prometheus.Counter](timeNow)),
	}
}

// UpdateTime updates the last access time to be annotated to any new or existing metric.
// It is a required operation before processing a given
// batch of metrics (invoking the WithLabelValues).
func (ex *Expirer) UpdateTime() {
	ex.entries.UpdateTime()
}

// WithLabelValues returns the Counter for the given slice of label
// values (same order as the variable labels in Desc). If that combination of
// label values is accessed for the first time, a new Counter is created.
// If not, a cached copy is returned and the "last access" cache time is updated.
func (ex *Expirer) WithLabelValues(lbls ...string) prometheus.Counter {
	return ex.entries.GetOrCreate(lbls, func() prometheus.Counter {
		plog().With("labelValues", lbls).Debug("storing new metric label set")
		return ex.wrapped.WithLabelValues(lbls...)
	})
}

// Describe wraps prometheus.Collector Describe method
func (ex *Expirer) Describe(descs chan<- *prometheus.Desc) {
	ex.wrapped.Describe(descs)
}

// Collect wraps prometheus.Collector Wrap method
func (ex *Expirer) Collect(metrics chan<- prometheus.Metric) {
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

package prom

import (
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var timeNow = time.Now

func plog() *slog.Logger {
	return slog.With("component", "prom.Expirer")
}

// Expirer drops metrics from labels that haven't been updated during a given timeout
// TODO: generify and move to a common section for using it also in AppO11y
type Expirer struct {
	mt         sync.RWMutex
	expireTime time.Duration
	timeNow    time.Time
	wrapped    *prometheus.CounterVec
	entries    map[string]*entry
}

type entry struct {
	lastAccess  time.Time
	labelValues []string
	count       prometheus.Counter
}

// NewExpirer creates a metric that wraps a given CounterVec. Its labeled instances are dropped
// if they haven't been updated during the last timeout period
func NewExpirer(wrapped *prometheus.CounterVec, expireTime time.Duration) *Expirer {
	return &Expirer{
		wrapped:    wrapped,
		expireTime: expireTime,
		entries:    map[string]*entry{},
	}
}

// UpdateTime updates the last access time to be annotated to any new or existing metric.
// It is a required operation before processing a given
// batch of metrics (invoking the WithLabelValues).
func (ex *Expirer) UpdateTime() {
	ex.timeNow = timeNow()
}

// WithLabelValues returns the Counter for the given slice of label
// values (same order as the variable labels in Desc). If that combination of
// label values is accessed for the first time, a new Counter is created.
// If not, a cached copy is returned and the "last access" cache time is updated.
func (ex *Expirer) WithLabelValues(lbls ...string) prometheus.Counter {
	h := labelsKey(lbls)
	ex.mt.RLock()
	e, ok := ex.entries[h]
	ex.mt.RUnlock()
	if ok {
		ex.mt.Lock()
		e.lastAccess = ex.timeNow
		ex.mt.Unlock()
		return e.count
	}

	plog().With("labelValues", lbls).Debug("storing new metric label set")
	c := ex.wrapped.WithLabelValues(lbls...)
	ex.mt.Lock()
	ex.entries[h] = &entry{
		labelValues: lbls,
		lastAccess:  ex.timeNow,
		count:       c,
	}
	ex.mt.Unlock()
	return c
}

func labelsKey(lbls []string) string {
	return strings.Join(lbls, ":")
}

// Describe wraps prometheus.Collector Describe method
func (ex *Expirer) Describe(descs chan<- *prometheus.Desc) {
	ex.wrapped.Describe(descs)
}

// Collect wraps prometheus.Collector Wrap method
func (ex *Expirer) Collect(metrics chan<- prometheus.Metric) {
	log := plog()
	log.Debug("invoking metrics collection")
	now := timeNow()
	var delKeys []string
	var delLabels [][]string
	ex.mt.RLock()
	for k, e := range ex.entries {
		if now.Sub(e.lastAccess) > ex.expireTime {
			delKeys = append(delKeys, k)
			delLabels = append(delLabels, e.labelValues)
		} else {
			metrics <- e.count
		}
	}
	ex.mt.RUnlock()
	ex.mt.Lock()
	for _, k := range delKeys {
		delete(ex.entries, k)
	}
	ex.mt.Unlock()
	for _, k := range delLabels {
		ex.wrapped.DeleteLabelValues(k...)
		log.With("labelValues", k).Debug("deleting old Prometheus metric")
	}
}

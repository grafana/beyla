package prom

import (
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const DefaultExpireTime = 3 * time.Minute

var timeNow = time.Now

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

func NewExpirer(wrapped *prometheus.CounterVec, expireTime time.Duration) *Expirer {
	return &Expirer{
		wrapped:    wrapped,
		expireTime: expireTime,
		entries:    map[string]*entry{},
	}
}

func (ex *Expirer) UpdateTime() {
	ex.timeNow = timeNow()
}

func (ex *Expirer) WithLabelValues(lbls ...string) prometheus.Counter {
	h := labelsKey(lbls)
	ex.mt.RLock()
	e, ok := ex.entries[h]
	if ok {
		e.lastAccess = ex.timeNow
		ex.mt.RUnlock()
		return e.count
	}
	ex.mt.RUnlock()

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

func (ex *Expirer) Describe(descs chan<- *prometheus.Desc) {
	ex.wrapped.Describe(descs)
}

func (ex *Expirer) Collect(metrics chan<- prometheus.Metric) {
	now := timeNow()
	var delKeys []string
	var delLabels [][]string
	for k, e := range ex.entries {
		if now.Sub(e.lastAccess) > ex.expireTime {
			delKeys = append(delKeys, k)
			delLabels = append(delLabels, e.labelValues)
		} else {
			metrics <- e.count
		}
	}
	for _, k := range delKeys {
		delete(ex.entries, k)
	}
	for _, k := range delLabels {
		ex.wrapped.DeleteLabelValues(k...)
	}
}

package export

import (
	"strings"
	"sync"
	"time"
)

// ExpiryMap stores elements in a synchronized map, and removes them if they haven't been
// accessed/updated for a given time period
type ExpiryMap[T any] struct {
	clock      func() time.Time
	mt         sync.RWMutex
	expireTime time.Duration
	timeNow    time.Time
	entries    map[string]*entry[T]
}

type entry[T any] struct {
	lastAccess  time.Time
	labelValues []string
	val         T
}

type ExpiryOption[T any] func(ex *ExpiryMap[T])

// WithClock is only required for unit tests
func WithClock[T any](clk func() time.Time) ExpiryOption[T] {
	return func(ex *ExpiryMap[T]) {
		ex.clock = clk
	}
}

// NewExpiryMap creates an expiry map. Its labeled instances are dropped
// if they haven't been updated during the last timeout period
func NewExpiryMap[T any](expireTime time.Duration, opts ...ExpiryOption[T]) *ExpiryMap[T] {
	em := &ExpiryMap[T]{
		expireTime: expireTime,
		entries:    map[string]*entry[T]{},
		clock:      time.Now,
	}
	for _, opt := range opts {
		opt(em)
	}
	return em
}

// UpdateTime updates the last access time to be annotated to any new or existing metric.
// It is a required operation before processing a given
// batch of metrics (e.g. before invoking GetOrCreate).
func (ex *ExpiryMap[T]) UpdateTime() {
	ex.timeNow = ex.clock()
}

// GetOrCreate returns the stored object for the given slice of label
// values. If that combination of
// label values is accessed for the first time, a new instance is created.
// If not, a cached copy is returned and the "last access" cache time is updated.
func (ex *ExpiryMap[T]) GetOrCreate(lbls []string, instancer func() T) T {
	h := labelsKey(lbls)
	ex.mt.RLock()
	e, ok := ex.entries[h]
	ex.mt.RUnlock()
	if ok {
		ex.mt.Lock()
		e.lastAccess = ex.timeNow
		ex.mt.Unlock()
		return e.val
	}
	ex.mt.Lock()
	instance := instancer()
	ex.entries[h] = &entry[T]{
		labelValues: lbls,
		lastAccess:  ex.timeNow,
		val:         instance,
	}
	ex.mt.Unlock()
	return instance
}

// DeleteExpired entries and return their label set
func (ex *ExpiryMap[T]) DeleteExpired() [][]string {
	var delKeys []string
	var delLabels [][]string
	ex.mt.RLock()
	now := ex.clock()
	for k, e := range ex.entries {
		if now.Sub(e.lastAccess) > ex.expireTime {
			delKeys = append(delKeys, k)
			delLabels = append(delLabels, e.labelValues)
		}
	}
	ex.mt.RUnlock()
	ex.mt.Lock()
	for _, k := range delKeys {
		delete(ex.entries, k)
	}
	ex.mt.Unlock()
	return delLabels
}

// All returns an array with all the stored entries. It might contain expired entries
// if DeleteExpired is not invoked before it.
// TODO: use https://tip.golang.org/wiki/RangefuncExperiment when available
func (ex *ExpiryMap[T]) All() []T {
	items := make([]T, 0, len(ex.entries))
	ex.mt.RLock()
	for _, e := range ex.entries {
		items = append(items, e.val)
	}
	ex.mt.RUnlock()
	return items
}

func labelsKey(lbls []string) string {
	return strings.Join(lbls, ":")
}

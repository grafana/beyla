// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package expire // import "go.opentelemetry.io/obi/pkg/export/expire"

import (
	"strings"
	"sync"
	"time"
)

type Clock func() time.Time

// ExpiryMap stores elements in a synchronized map, and removes them if they haven't been
// accessed/updated for a given time period
// TODO: optimize to minimize memory generation
type ExpiryMap[T any] struct {
	clock   Clock
	mt      sync.RWMutex
	ttl     time.Duration
	entries map[string]*entry[T]
}

type entry[T any] struct {
	lastAccess  time.Time
	labelValues []string
	val         T
}

// NewExpiryMap creates an expiry map given a Clock implementation and a TTL.
// Its labeled instances are dropped if they haven't been updated during the
// last timeout period
func NewExpiryMap[T any](clock Clock, ttl time.Duration) *ExpiryMap[T] {
	em := &ExpiryMap[T]{
		ttl:     ttl,
		entries: map[string]*entry[T]{},
		clock:   clock,
	}
	return em
}

// GetOrCreate returns the stored object for the given slice of label
// values. If that combination of
// label values is accessed for the first time, a new instance is created.
// If not, a cached copy is returned and the "last access" cache time is updated.
func (ex *ExpiryMap[T]) GetOrCreate(lbls []string, instancer func() T) T {
	now := ex.clock()

	h := labelsKey(lbls)
	ex.mt.RLock()
	e, ok := ex.entries[h]
	ex.mt.RUnlock()
	if ok {
		ex.mt.Lock()
		e.lastAccess = now
		ex.mt.Unlock()
		return e.val
	}
	ex.mt.Lock()
	instance := instancer()
	ex.entries[h] = &entry[T]{
		labelValues: lbls,
		lastAccess:  now,
		val:         instance,
	}
	ex.mt.Unlock()
	return instance
}

// DeleteExpired entries and return their label set
func (ex *ExpiryMap[T]) DeleteExpired() []T {
	// If TTL is 0, disable expiration completely
	if ex.ttl == 0 {
		return nil
	}

	var delKeys []string
	var delEntries []T
	ex.mt.RLock()
	now := ex.clock()
	for k, e := range ex.entries {
		if now.Sub(e.lastAccess) > ex.ttl {
			delKeys = append(delKeys, k)
			delEntries = append(delEntries, e.val)
		}
	}
	ex.mt.RUnlock()
	ex.mt.Lock()
	for _, k := range delKeys {
		delete(ex.entries, k)
	}
	ex.mt.Unlock()
	return delEntries
}

// DeleteAll cleans the map and returns a slice with its deleted elements
func (ex *ExpiryMap[T]) DeleteAll() []T {
	ex.mt.Lock()
	defer ex.mt.Unlock()
	entries := make([]T, 0, len(ex.entries))
	for k, e := range ex.entries {
		entries = append(entries, e.val)
		delete(ex.entries, k)
	}
	return entries
}

// All returns an array with all the stored entries. It might contain expired entries
// if DeleteExpired is not invoked before it.
// TODO: use https://tip.golang.org/wiki/RangefuncExperiment when available
func (ex *ExpiryMap[T]) All() []T {
	ex.mt.RLock()
	items := make([]T, 0, len(ex.entries))
	for _, e := range ex.entries {
		items = append(items, e.val)
	}
	ex.mt.RUnlock()
	return items
}

func labelsKey(lbls []string) string {
	return strings.Join(lbls, ":")
}

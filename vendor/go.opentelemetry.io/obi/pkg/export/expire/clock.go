// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package expire // import "go.opentelemetry.io/obi/pkg/export/expire"

import (
	"sync"
	"time"
)

// CachedClock is a clock that is only updated on demand. Until the
// Update method is not invoked, the Time method will return always
// the same value.
// Its main purpose is to avoid too many time.Now syscalls in scenarios
// with thousands of processed flows per second.
type CachedClock struct {
	now       time.Time
	baseClock func() time.Time
	mu        sync.Mutex
}

func NewCachedClock(baseClock func() time.Time) *CachedClock {
	return &CachedClock{
		now:       baseClock(),
		baseClock: baseClock,
	}
}

// Update the CachedClock time according to its base clock.
func (ex *CachedClock) Update() {
	ex.mu.Lock()
	defer ex.mu.Unlock()
	ex.now = ex.baseClock()
}

// Time returns the time returned by the base clock the last time
// that the Update method was invoked.
func (ex *CachedClock) Time() time.Time {
	ex.mu.Lock()
	defer ex.mu.Unlock()
	return ex.now
}

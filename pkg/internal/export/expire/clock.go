package expire

import "time"

type CachedClock struct {
	now       time.Time
	baseClock func() time.Time
}

func NewCachedClock(baseClock func() time.Time) *CachedClock {
	return &CachedClock{
		now:       baseClock(),
		baseClock: baseClock,
	}
}

func (ex *CachedClock) Update() {
	ex.now = ex.baseClock()
}

func (ex *CachedClock) Time() time.Time {
	return ex.now
}

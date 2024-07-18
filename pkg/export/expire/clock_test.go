package expire

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestClock(t *testing.T) {
	// GIVEN a cached clock
	fakeTime := time.Date(2023, 12, 1, 12, 34, 56, 0, time.UTC)
	clock := NewCachedClock(func() time.Time {
		return fakeTime
	})

	// THAT returns the time
	assert.Equal(t, time.Date(2023, 12, 1, 12, 34, 56, 0, time.UTC), clock.Time())

	// WHEN the time passes but it is not explicitly updated
	fakeTime = time.Date(2024, 12, 10, 12, 34, 56, 0, time.UTC)

	// THEN the returned time is not updated
	assert.Equal(t, time.Date(2023, 12, 1, 12, 34, 56, 0, time.UTC), clock.Time())

	// AND WHEN the clock is explicitly updated
	clock.Update()

	// THEN the returned time is updated too
	assert.Equal(t, time.Date(2024, 12, 10, 12, 34, 56, 0, time.UTC), clock.Time())
}

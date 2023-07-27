package testutil

import (
	"testing"
	"time"
)

// ReadChannel tries to read a message from a channel and returns it. If there isn't any
// message after the given timeout, it fails the provided test
func ReadChannel[T any](t *testing.T, inCh <-chan T, timeout time.Duration) T {
	t.Helper()
	var item T
	select {
	case item = <-inCh:
		return item
	case <-time.After(timeout):
		t.Fatalf("timeout (%s) while waiting for event in input channel", timeout)
	}
	return item
}

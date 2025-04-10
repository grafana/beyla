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

// ChannelEmpty asserts that a channel is empty and does not receive any message,
// giving a timeout as margin to check that no actual messages are received during that Duration.
func ChannelEmpty[T any](t *testing.T, inCh <-chan T, timeout time.Duration) {
	t.Helper()
	select {
	case stuff, ok := <-inCh:
		if ok {
			t.Fatalf("channel should be empty. Got %#v", stuff)
		}
	case <-time.After(timeout):
		// ok, channel is empty!
	}
}

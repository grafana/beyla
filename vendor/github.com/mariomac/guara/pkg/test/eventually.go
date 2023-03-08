package test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type eventuallyConfig struct {
	interval time.Duration
}

var defaultEventuallyConfig = eventuallyConfig{
	interval: 0,
}

type EventuallyOption func(cfg *eventuallyConfig)

// Interval to wait between successive executions of the inner test in the same Eventually
// invocation, if the inner test has failed.
func Interval(t time.Duration) EventuallyOption {
	return func(cfg *eventuallyConfig) {
		cfg.interval = t
	}
}

// Eventually retries a test until it eventually succeeds. If the timeout is reached, the test fails
// with the same failure as its last execution.
func Eventually(t *testing.T, timeout time.Duration, testFunc func(_ require.TestingT), options ...EventuallyOption) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	config := defaultEventuallyConfig
	for _, opt := range options {
		opt(&config)
	}

	success := make(chan interface{})
	errorCh := make(chan error)
	failCh := make(chan error)

	go func() {
		for ctx.Err() == nil {
			result := testResult{failed: false, errorCh: errorCh, failCh: failCh}
			// Executing the function to test
			testFunc(&result)
			// If the function didn't reported failure and didn't reached timeout
			if !result.HasFailed() && ctx.Err() == nil {
				success <- 1
				break
			}
			// Otherwise, we wait for the passed interval
			time.Sleep(config.interval)
		}
	}()

	// Wait for success or timeout
	var err, fail error
	for {
		select {
		case <-success:
			return
		case err = <-errorCh:
		case fail = <-failCh:
		case <-ctx.Done():
			if err != nil {
				t.Error(err)
			} else if fail != nil {
				t.Error(fail)
			} else {
				t.Error("timeout while waiting for test to complete")
			}
			return
		}
	}
}

// util class for Eventually
type testResult struct {
	sync.RWMutex
	failed  bool
	errorCh chan<- error
	failCh  chan<- error
}

func (te *testResult) Errorf(format string, args ...interface{}) {
	te.Lock()
	te.failed = true
	te.Unlock()
	te.errorCh <- fmt.Errorf(format, args...)
}

func (te *testResult) FailNow() {
	te.Lock()
	te.failed = true
	te.Unlock()
	te.failCh <- errors.New("test failed")
}

func (te *testResult) HasFailed() bool {
	te.RLock()
	defer te.RUnlock()
	return te.failed
}

package test

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync/atomic"
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
			result := testResult{errorCh: errorCh, fatalCh: failCh}
			// Executing the function to test
			// since FailNow interrupts the running goroutine to avoid executing the
			// later tests, we need to run the test function in a different goroutine each time
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				testFunc(&result)
			}()
			<-finished
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
	var err, fatal error
	for {
		select {
		case <-success:
			return
		case err = <-errorCh:
		case fatal = <-failCh:
		case <-ctx.Done():
			if fatal != nil {
				if err != nil {
					t.Fatal(err)
				} else {
					t.Fatal()
				}
			} else if err != nil {
				t.Error(err)
			} else {
				t.Error("timeout while waiting for test to complete")
			}
			return
		}
	}
}

// util class for Eventually
type testResult struct {
	failed atomic.Bool
	// anything received by the errorCh will mark the test as failed, but continuing its execution
	errorCh chan<- error
	// anything received by the fatalCh will mark the test as failed and stopping its execution
	fatalCh chan<- error
}

func (te *testResult) Errorf(format string, args ...interface{}) {
	te.failed.Store(true)
	te.errorCh <- fmt.Errorf(format, args...)
}

func (te *testResult) FailNow() {
	te.failed.Store(true)
	te.fatalCh <- errors.New("test failed")
	// stops the current goroutine
	runtime.Goexit()
}

func (te *testResult) HasFailed() bool {
	return te.failed.Load()
}

// Package swarm provides tools for the creation and coordination of the nodes that go inside the different
// Beyla pipelines
package swarm

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
)

// RunFunc is a function that runs a node. The node should be stoppable via the passed context Done function.
type RunFunc func(context.Context)

// EmptyRunFunc returns a no-op RunFunc that does nothing. Can be used as a convenience method
// for an Instancer that returns a function that can be ignored
func EmptyRunFunc() (RunFunc, error) {
	return func(_ context.Context) {}, nil
}

// Bypass is a convenience method that bypasses the input channel to the output channel and returns a
// no-op RunFunc. It can be used as a convenience method for an Instancer of an optional node
// that might not be instantiated and its input-output need to be bypassed from its sender to its receiver.
func Bypass[T any](input, output *msg.Queue[T]) (RunFunc, error) {
	input.Bypass(output)
	return EmptyRunFunc()
}

type runnerMeta struct {
	id   string
	fn   RunFunc
	done atomic.Bool
}

// Runner runs all the nodes in the swarm returned from an Instancer.
type Runner struct {
	started            atomic.Bool
	runners            []runnerMeta
	done               chan error
	cancelTimeout      time.Duration
	cancelInstancerCtx func()
}

// Start the Swarm in background. It calls all registered service creators and, if all succeed,
// it runs the returned RunFunc instances.
// If any of the creators return an error, the swarm will stop and return the error. The context
// that is passed to the rest of creators will be cancelled.
// No service RunFunc internal instance is started until all the Creators are successfully
// created. This means that if any of the creators fail, no service RunFunc is started.
func (s *Runner) Start(ctx context.Context, opts ...StartOpt) {
	if s.started.Swap(true) {
		panic("swarm.Runner already started")
	}
	for _, opt := range opts {
		opt(s)
	}
	s.done = make(chan error, 1)
	doneClosed := false
	doneCloseMutex := sync.Mutex{}
	wg := sync.WaitGroup{}
	wg.Add(len(s.runners))
	go func() {
		wg.Wait()
		// the context previously passed in the InstanceFunc is also
		// canceled when the swarm stops running, to avoid context leaking
		s.cancelInstancerCtx()
		doneCloseMutex.Lock()
		defer doneCloseMutex.Unlock()
		doneClosed = true
		close(s.done)
	}()
	for i := range s.runners {
		runner := &s.runners[i]
		go func() {
			runner.fn(ctx)
			wg.Done()
			runner.done.Store(true)
		}()
	}
	if s.cancelTimeout > 0 {
		go s.watchForRunnersExiting(ctx, &wg, &doneCloseMutex, &doneClosed)
	}
}

// watchForRunnersExiting waits for the main context to complete and, check that all the runners
// have ended before a given timeout
func (s *Runner) watchForRunnersExiting(ctx context.Context, wg *sync.WaitGroup, doneCloseMutex *sync.Mutex, doneClosed *bool) {
	// wait for the context to be canceled
	<-ctx.Done()
	allRunnersClosed := make(chan struct{})
	go func() {
		wg.Wait()
		close(allRunnersClosed)
	}()
	select {
	case <-allRunnersClosed:
		// ok!
	case <-time.After(s.cancelTimeout):
		// collect all the running instances
		var ids []string
		for i := range s.runners {
			r := &s.runners[i]
			if !r.done.Load() {
				ids = append(ids, r.id)
			}
		}
		// it might happen that, during the collection of instances
		// all the runners have exited, so we just exit successfully
		// and avoid sending any error
		doneCloseMutex.Lock()
		defer doneCloseMutex.Unlock()
		if *doneClosed || len(ids) == 0 {
			return
		}
		s.done <- CancelTimeoutError{timeout: s.cancelTimeout, runningIDs: ids}
	}
}

// Done returns a channel that is closed when all the nodes in the swarm Runner have finished their execution.
// If there is an internal error (for example, if some nodes of the graph don't properly exit after the main
// context is canceled), the channel returns an error.
func (s *Runner) Done() <-chan error {
	return s.done
}

// StartOpt defines options for the Runner's Start method
type StartOpt func(*Runner)

// WithCancelTimeout will cause that the Done() method returns an error
// if the context passed to the Start(ctx) method is canceled but any of the
// internal RunFunc don't exit within the provided timeout
func WithCancelTimeout(timeout time.Duration) StartOpt {
	return func(runner *Runner) {
		runner.cancelTimeout = timeout
	}
}

type CancelTimeoutError struct {
	timeout    time.Duration
	runningIDs []string
}

func (c CancelTimeoutError) Error() string {
	return fmt.Sprintf("nodes don't finishing %s after canceling the context: %v",
		c.timeout, strings.Join(c.runningIDs, ", "))
}

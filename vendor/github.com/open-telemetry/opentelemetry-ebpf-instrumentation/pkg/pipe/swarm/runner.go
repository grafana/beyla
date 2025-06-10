// Package swarm provides tools for the creation and coordination of the nodes that go inside the different
// Beyla pipelines
package swarm

import (
	"context"
	"sync"
	"sync/atomic"

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

// Runner runs all the nodes in the swarm returned from an Instancer.
type Runner struct {
	started atomic.Bool
	runners []RunFunc
	done    chan struct{}

	cancelInstancerCtx func()
}

// Start the Swarm in background. It calls all registered service creators and, if all succeed,
// it runs the returned RunFunc instances.
// If any of the creators return an error, the swarm will stop and return the error. The context
// that is passed to the rest of creators will be cancelled.
// No service RunFunc internal instance is started until all the Creators are successfully
// created. This means that if any of the creators fail, no service RunFunc is started.
func (s *Runner) Start(ctx context.Context) {
	if s.started.Swap(true) {
		panic("swarm.Runner already started")
	}
	s.done = make(chan struct{})
	wg := sync.WaitGroup{}
	wg.Add(len(s.runners))
	go func() {
		wg.Wait()
		// the context previously passed in the InstanceFunc is also
		// canceled when the swarm stops running, to avoid context leaking
		s.cancelInstancerCtx()
		close(s.done)
	}()
	for i := range s.runners {
		go func() {
			s.runners[i](ctx)
			wg.Done()
		}()
	}
}

// Done returns a channel that is closed when all the nodes in the swarm Runner have finished their execution.
func (s *Runner) Done() <-chan struct{} {
	return s.done
}

// Package swarm provides tools for the creation and coordination of the nodes that go inside the different
// Beyla pipelines
package swarm

import (
	"context"
	"sync/atomic"
)

// RunFunc is a function that runs a node. The node should be stoppable via the passed context Done function.
type RunFunc func(context.Context)

// EmptyRunFunc returns a no-op RunFunc that does nothing. Can be used as a convenience reference
// for an Instancer that returns a function that can be ignored
func EmptyRunFunc() (RunFunc, error) {
	return func(_ context.Context) {}, nil
}

// Runner runs all the nodes in the swarm returned from an Instancer.
type Runner struct {
	started atomic.Bool
	runners []RunFunc
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
	for i := range s.runners {
		go s.runners[i](ctx)
	}
}

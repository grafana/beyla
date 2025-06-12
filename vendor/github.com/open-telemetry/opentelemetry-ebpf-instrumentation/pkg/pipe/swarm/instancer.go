package swarm

import (
	"context"
	"fmt"
	"sync"
)

// InstanceFunc is a function that creates a service RunFunc.
// The passed context will be cancelled by the Instancer's Instance method
// if any of the nodes in the same swarm returned error in its instantiation,
// and/or when the returned Runner instance finishes its execution
type InstanceFunc func(context.Context) (RunFunc, error)

// Instancer coordinates the instantiation of all the swarm nodes and
// manages any error during the construction of it.
type Instancer struct {
	mt       sync.Mutex
	creators []instanceMeta
}

// Add a service instancer to the swarm. The intancer will be called when the swarm Instance starts,
// and must return a RunFunc instance that will execute the actual operation of the service node.
func (s *Instancer) Add(c InstanceFunc, opts ...AddOpt) {
	s.mt.Lock()
	defer s.mt.Unlock()
	im := instanceMeta{
		// if no explicit ID is provided, it would show the order in which the InstanceFunc is added
		id: fmt.Sprintf("#%d", len(s.creators)),
		fn: c,
	}
	for _, opt := range opts {
		opt(&im)
	}
	s.creators = append(s.creators, im)
}

// Instance the Swarm. It calls all registered service creators and, if all succeed,
// returns a Runner instance that will execute the actual operation of the service nodes.
func (s *Instancer) Instance(ctx context.Context) (*Runner, error) {
	s.mt.Lock()
	defer s.mt.Unlock()
	runner := &Runner{runners: make([]runnerMeta, 0, len(s.creators))}
	var buildCtx context.Context
	buildCtx, runner.cancelInstancerCtx = context.WithCancel(ctx)
	for _, creator := range s.creators {
		runFn, err := creator.fn(buildCtx)
		if err != nil {
			runner.cancelInstancerCtx()
			return nil, err
		}
		runner.runners = append(runner.runners, runnerMeta{
			id: creator.id,
			fn: runFn,
		})
	}
	return runner, nil
}

// DirectInstance provides a shortcut to provide the Instancer with a RunFunc that is already instanced, or
// whose creation does not require any error handling API.
func DirectInstance(r RunFunc) InstanceFunc {
	return func(_ context.Context) (RunFunc, error) {
		return r, nil
	}
}

type instanceMeta struct {
	id string
	fn InstanceFunc
}

// AddOpt allows overriding the behavior of the Instancer's Add method
type AddOpt func(*instanceMeta)

// WithID associates the added InstanceFunc with an ID that would allow identify it
// in case it detects a zombie RunFunc
func WithID(id string) AddOpt {
	return func(i *instanceMeta) {
		i.id = id
	}
}

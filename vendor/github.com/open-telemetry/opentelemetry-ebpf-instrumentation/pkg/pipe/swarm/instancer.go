package swarm

import (
	"context"
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
	creators []InstanceFunc
}

// Add a service instancer to the swarm. The intancer will be called when the swarm Instance starts,
// and must return a RunFunc instance that will execute the actual operation of the service node.
func (s *Instancer) Add(c InstanceFunc) {
	s.mt.Lock()
	defer s.mt.Unlock()
	s.creators = append(s.creators, c)
}

// Instance the Swarm. It calls all registered service creators and, if all succeed,
// returns a Runner instance that will execute the actual operation of the service nodes.
func (s *Instancer) Instance(ctx context.Context) (*Runner, error) {
	s.mt.Lock()
	defer s.mt.Unlock()
	runner := &Runner{runners: make([]RunFunc, 0, len(s.creators))}
	var buildCtx context.Context
	buildCtx, runner.cancelInstancerCtx = context.WithCancel(ctx)
	for _, creator := range s.creators {
		runFn, err := creator(buildCtx)
		if err != nil {
			runner.cancelInstancerCtx()
			return nil, err
		}
		runner.runners = append(runner.runners, runFn)
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

package swarm

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSwarm_BuildWithError(t *testing.T) {
	inst := Instancer{}
	inst.Add(func(_ context.Context) (RunFunc, error) {
		return nil, errors.New("creation error")
	})
	_, err := inst.Instance(context.Background())
	assert.Error(t, err)
}

func TestSwarm_StartTwice(t *testing.T) {
	inst := Instancer{}
	inst.Add(func(_ context.Context) (RunFunc, error) {
		return func(_ context.Context) {}, nil
	})
	s, err := inst.Instance(context.Background())
	require.NoError(t, err)
	s.Start(context.Background())
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic, got none")
		}
	}()
	s.Start(context.Background())
}

func TestSwarm_RunnerExecution(t *testing.T) {
	inst := Instancer{}
	runnerExecuted := atomic.Bool{}
	inst.Add(DirectInstance(func(_ context.Context) {
		runnerExecuted.Store(true)
	}))
	s, err := inst.Instance(context.Background())
	require.NoError(t, err)
	s.Start(context.Background())
	test.Eventually(t, 5*time.Second, func(t require.TestingT) {
		assert.True(t, runnerExecuted.Load(), "runner was not executed")
	})
	assertDone(t, s)
}

func TestSwarm_CreatorFailure(t *testing.T) {
	inst := Instancer{}
	runnerStarted := atomic.Bool{}
	c1cancel := atomic.Bool{}
	c3exec := atomic.Bool{}
	inst.Add(func(ctx context.Context) (RunFunc, error) {
		go func() {
			<-ctx.Done()
			c1cancel.Store(true)
		}()
		return func(_ context.Context) {
			runnerStarted.Store(true)
		}, nil
	})
	inst.Add(func(_ context.Context) (RunFunc, error) {
		return nil, errors.New("creation error")
	})
	inst.Add(func(_ context.Context) (RunFunc, error) {
		c3exec.Store(true)
		return func(_ context.Context) {}, nil
	})

	// second creator fails, so the first one should be cancelled and the third one should not be instantiated
	_, err := inst.Instance(context.Background())
	require.Error(t, err)
	test.Eventually(t, 5*time.Second, func(t require.TestingT) {
		assert.True(t, c1cancel.Load(), "c1 was not cancelled")
	})
	assert.False(t, c3exec.Load(), "c3 was executed")
	assert.False(t, runnerStarted.Load(), "runner was started")
}

func TestSwarm_ContextPassed(t *testing.T) {
	startWg := sync.WaitGroup{}
	startWg.Add(3)
	doneWg := sync.WaitGroup{}
	doneWg.Add(3)
	inst := Instancer{}
	innerRunner := func(ctx context.Context) {
		startWg.Done()
		<-ctx.Done()
		doneWg.Done()
	}
	inst.Add(func(_ context.Context) (RunFunc, error) { return innerRunner, nil })
	inst.Add(func(_ context.Context) (RunFunc, error) { return innerRunner, nil })
	inst.Add(func(_ context.Context) (RunFunc, error) { return innerRunner, nil })
	ctx, cancel := context.WithCancel(context.Background())
	s, err := inst.Instance(context.Background())
	require.NoError(t, err)
	s.Start(ctx)
	test.Eventually(t, 5*time.Second, func(_ require.TestingT) {
		startWg.Wait()
	})
	cancel()
	test.Eventually(t, 5*time.Second, func(_ require.TestingT) {
		doneWg.Wait()
	})
	assertDone(t, s)
}

func assertDone(t *testing.T, s *Runner) {
	timeout := time.After(5 * time.Second)
	select {
	case <-s.Done():
		// ok!!!
	case <-timeout:
		t.Fatal("Runner instance did not properly finish")
	}
}

package process

import (
	"context"
	"testing"
	"time"

	"github.com/shirou/gopsutil/process"
	"github.com/stretchr/testify/assert"

	"github.com/grafana/beyla/pkg/internal/testutil"
)

const testTimeout = 5 * time.Second

func TestWatcher_Poll(t *testing.T) {
	// mocking a fake process.Processes function
	p1 := &process.Process{Pid: 1}
	p2 := &process.Process{Pid: 2}
	p3 := &process.Process{Pid: 3}
	p4 := &process.Process{Pid: 4}
	invocation := 0
	ctx, cancel := context.WithCancel(context.Background())
	// GIVEN a pollAccounter
	acc := pollAccounter{
		interval: time.Microsecond,
		ctx:      ctx,
		pids:     map[int32]*process.Process{},
		listProcesses: func() ([]*process.Process, error) {
			invocation++
			switch invocation {
			case 1:
				return []*process.Process{p1, p2, p3}, nil
			case 2:
				return []*process.Process{p1, p3, p4}, nil
			default:
				return []*process.Process{p2, p3, p4}, nil
			}
		},
	}
	accounterOutput := make(chan []WatchEvent, 1)
	accounterExited := make(chan struct{})
	go func() {
		acc.Run(accounterOutput)
		close(accounterExited)
	}()

	// WHEN it polls the process for the first time
	// THEN it returns the creation of all the events
	out := testutil.ReadChannel(t, accounterOutput, testTimeout)
	assert.Equal(t, []WatchEvent{
		{Type: EventCreated, Process: p1},
		{Type: EventCreated, Process: p2},
		{Type: EventCreated, Process: p3},
	}, out)

	// WHEN it polls the process for the successive times
	// THEN it returns the creation the new processes
	// AND the deletion of the old processes
	out = testutil.ReadChannel(t, accounterOutput, testTimeout)
	assert.Equal(t, []WatchEvent{
		{Type: EventCreated, Process: p4},
		{Type: EventDeleted, Process: p2},
	}, out)
	out = testutil.ReadChannel(t, accounterOutput, testTimeout)
	assert.Equal(t, []WatchEvent{
		{Type: EventCreated, Process: p2},
		{Type: EventDeleted, Process: p1},
	}, out)

	// WHEN no changes in the process, it doesn't send anything
	select {
	case procs := <-accounterOutput:
		assert.Failf(t, "no output expected", "got %v", procs)
	default:
		// ok!
	}

	// WHEN its context is cancelled
	cancel()
	// THEN the main loop exits
	select {
	case <-accounterExited:
	// ok!
	case <-time.After(testTimeout):
		assert.Fail(t, "expected to exit the main loop")
	}
}

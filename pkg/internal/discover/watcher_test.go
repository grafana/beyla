package discover

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/grafana/beyla/pkg/internal/discover/services"
	"github.com/grafana/beyla/pkg/internal/testutil"
)

const testTimeout = 5 * time.Second

func TestWatcher_Poll(t *testing.T) {
	// mocking a fake services.ProcessInfoes function

	p1_1 := &services.ProcessInfo{Pid: 1, OpenPorts: []uint32{3030}}
	p1_2 := &services.ProcessInfo{Pid: 1, OpenPorts: []uint32{3030, 3031}}
	p2 := &services.ProcessInfo{Pid: 2, OpenPorts: []uint32{123}}
	p3 := &services.ProcessInfo{Pid: 3, OpenPorts: []uint32{456}}
	p4 := &services.ProcessInfo{Pid: 4, OpenPorts: []uint32{789}}
	invocation := 0
	ctx, cancel := context.WithCancel(context.Background())
	// GIVEN a pollAccounter
	acc := pollAccounter{
		interval: time.Microsecond,
		ctx:      ctx,
		pidPorts: map[pidPort]*services.ProcessInfo{},
		listProcesses: func() (map[int32]*services.ProcessInfo, error) {
			invocation++
			switch invocation {
			case 1:
				return map[int32]*services.ProcessInfo{p1_1.Pid: p1_1, p2.Pid: p2, p3.Pid: p3}, nil
			case 2:
				// p1_2 simulates that a new connection has been created for an existing process
				return map[int32]*services.ProcessInfo{p1_2.Pid: p1_2, p3.Pid: p3, p4.Pid: p4}, nil
			default:
				return map[int32]*services.ProcessInfo{p2.Pid: p2, p3.Pid: p3, p4.Pid: p4}, nil
			}
		},
	}
	accounterOutput := make(chan []Event[*services.ProcessInfo], 1)
	accounterExited := make(chan struct{})
	go func() {
		acc.Run(accounterOutput)
		close(accounterExited)
	}()

	// WHEN it polls the process for the first time
	// THEN it returns the creation of all the events
	out := testutil.ReadChannel(t, accounterOutput, testTimeout)
	assert.Equal(t, []Event[*services.ProcessInfo]{
		{Type: EventCreated, Obj: p1_1},
		{Type: EventCreated, Obj: p2},
		{Type: EventCreated, Obj: p3},
	}, sort(out))

	// WHEN it polls the process for the successive times
	// THEN it returns the creation of the new processes/connections
	// AND the deletion of the old processes
	out = testutil.ReadChannel(t, accounterOutput, testTimeout)
	assert.Equal(t, []Event[*services.ProcessInfo]{
		{Type: EventCreated, Obj: p1_2},
		{Type: EventDeleted, Obj: p2},
		{Type: EventCreated, Obj: p4},
	}, sort(out))
	out = testutil.ReadChannel(t, accounterOutput, testTimeout)
	assert.Equal(t, []Event[*services.ProcessInfo]{
		{Type: EventDeleted, Obj: p1_2},
		{Type: EventCreated, Obj: p2},
	}, sort(out))

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

// auxiliary function just to allow comparing slices whose order is not deterministic
func sort(events []Event[*services.ProcessInfo]) []Event[*services.ProcessInfo] {
	slices.SortFunc(events, func(a, b Event[*services.ProcessInfo]) int {
		return int(a.Obj.Pid) - int(b.Obj.Pid)
	})
	return events
}

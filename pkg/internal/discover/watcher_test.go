package discover

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	bpfWatcher "github.com/grafana/beyla/pkg/internal/ebpf/watcher"
	"github.com/grafana/beyla/pkg/internal/testutil"
)

const testTimeout = 50 * time.Second

func TestWatcher_Poll(t *testing.T) {
	// mocking a fake listProcesses method
	p1_1 := processPorts{pid: 1, openPorts: []uint32{3030}}
	p1_2 := processPorts{pid: 1, openPorts: []uint32{3030, 3031}}
	p2 := processPorts{pid: 2, openPorts: []uint32{123}}
	p3 := processPorts{pid: 3, openPorts: []uint32{456}}
	p4 := processPorts{pid: 4, openPorts: []uint32{789}}
	p5 := processPorts{pid: 10}
	invocation := 0
	ctx, cancel := context.WithCancel(context.Background())
	// GIVEN a pollAccounter
	acc := pollAccounter{
		interval: time.Microsecond,
		ctx:      ctx,
		pidPorts: map[pidPort]processPorts{},
		listProcesses: func(bool) (map[PID]processPorts, error) {
			invocation++
			switch invocation {
			case 1:
				return map[PID]processPorts{p1_1.pid: p1_1, p2.pid: p2, p3.pid: p3}, nil
			case 2:
				// p1_2 simulates that a new connection has been created for an existing process
				return map[PID]processPorts{p1_2.pid: p1_2, p3.pid: p3, p4.pid: p4}, nil
			case 3:
				return map[PID]processPorts{p2.pid: p2, p3.pid: p3, p4.pid: p4}, nil
			default:
				// new processes with no connections (p5) should be also reported
				return map[PID]processPorts{p5.pid: p5, p2.pid: p2, p3.pid: p3, p4.pid: p4}, nil
			}
		},
		executableReady: func(PID) bool {
			return true
		},
		loadBPFWatcher: func(*bpfWatcher.Watcher) error {
			return nil
		},
	}
	accounterOutput := make(chan []Event[processPorts], 1)
	accounterExited := make(chan struct{})
	go func() {
		acc.Run(accounterOutput)
		close(accounterExited)
	}()

	// WHEN it polls the process for the first time
	// THEN it returns the creation of all the events
	out := testutil.ReadChannel(t, accounterOutput, testTimeout)
	assert.Equal(t, []Event[processPorts]{
		{Type: EventCreated, Obj: p1_1},
		{Type: EventCreated, Obj: p2},
		{Type: EventCreated, Obj: p3},
	}, sort(out))

	// WHEN it polls the process for the successive times
	// THEN it returns the creation of the new processes/connections
	// AND the deletion of the old processes
	out = testutil.ReadChannel(t, accounterOutput, testTimeout)
	assert.Equal(t, []Event[processPorts]{
		{Type: EventCreated, Obj: p1_2},
		{Type: EventDeleted, Obj: p2},
		{Type: EventCreated, Obj: p4},
	}, sort(out))
	out = testutil.ReadChannel(t, accounterOutput, testTimeout)
	assert.Equal(t, []Event[processPorts]{
		{Type: EventDeleted, Obj: p1_2},
		{Type: EventCreated, Obj: p2},
	}, sort(out))

	// WHEN a new process with no connections is created
	// THEN it should be also reported
	// (use case: we want to later match by executable path a client process with short-lived connections)
	out = testutil.ReadChannel(t, accounterOutput, testTimeout)
	assert.Equal(t, []Event[processPorts]{
		{Type: EventCreated, Obj: p5},
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
func sort(events []Event[processPorts]) []Event[processPorts] {
	slices.SortFunc(events, func(a, b Event[processPorts]) int {
		return int(a.Obj.pid) - int(b.Obj.pid)
	})
	return events
}

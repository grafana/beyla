package discover

import (
	"bytes"
	"context"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/testutil"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/internal/ebpf/watcher"
)

const testTimeout = 5 * time.Second

func TestWatcher_Poll(t *testing.T) {
	// mocking a fake listProcesses method
	p1_1 := processAttrs{pid: 1, openPorts: []uint32{3030}}
	p1_2 := processAttrs{pid: 1, openPorts: []uint32{3030, 3031}}
	p2 := processAttrs{pid: 2, openPorts: []uint32{123}}
	p3 := processAttrs{pid: 3, openPorts: []uint32{456}}
	p4 := processAttrs{pid: 4, openPorts: []uint32{789}}
	p5 := processAttrs{pid: 10}
	invocation := 0
	ctx, cancel := context.WithCancel(context.Background())
	// GIVEN a pollAccounter
	acc := pollAccounter{
		interval: time.Microsecond,
		cfg:      &beyla.Config{},
		pidPorts: map[pidPort]processAttrs{},
		listProcesses: func(bool) (map[PID]processAttrs, error) {
			invocation++
			switch invocation {
			case 1:
				return map[PID]processAttrs{p1_1.pid: p1_1, p2.pid: p2, p3.pid: p3}, nil
			case 2:
				// p1_2 simulates that a new connection has been created for an existing process
				return map[PID]processAttrs{p1_2.pid: p1_2, p3.pid: p3, p4.pid: p4}, nil
			case 3:
				return map[PID]processAttrs{p2.pid: p2, p3.pid: p3, p4.pid: p4}, nil
			default:
				// new processes with no connections (p5) should be also reported
				return map[PID]processAttrs{p5.pid: p5, p2.pid: p2, p3.pid: p3, p4.pid: p4}, nil
			}
		},
		executableReady: func(PID) (string, bool) {
			return "", true
		},
		loadBPFWatcher: func(context.Context, *beyla.Config, chan<- watcher.Event) error {
			return nil
		},
		loadBPFLogger: func(context.Context, *beyla.Config) error {
			return nil
		},
		output: msg.NewQueue[[]Event[processAttrs]](msg.ChannelBufferLen(1)),
	}
	accounterOutput := acc.output.Subscribe()
	accounterExited := make(chan struct{})
	go func() {
		acc.run(ctx)
		close(accounterExited)
	}()

	// WHEN it polls the process for the first time
	// THEN it returns the creation of all the events
	out := testutil.ReadChannel(t, accounterOutput, testTimeout)
	assert.Equal(t, []Event[processAttrs]{
		{Type: EventCreated, Obj: p1_1},
		{Type: EventCreated, Obj: p2},
		{Type: EventCreated, Obj: p3},
	}, sort(out))

	// WHEN it polls the process for the successive times
	// THEN it returns the creation of the new processes/connections
	// AND the deletion of the old processes
	out = testutil.ReadChannel(t, accounterOutput, testTimeout)
	assert.Equal(t, []Event[processAttrs]{
		{Type: EventCreated, Obj: p1_2},
		{Type: EventDeleted, Obj: p2},
		{Type: EventCreated, Obj: p4},
	}, sort(out))
	out = testutil.ReadChannel(t, accounterOutput, testTimeout)
	assert.Equal(t, []Event[processAttrs]{
		{Type: EventDeleted, Obj: p1_2},
		{Type: EventCreated, Obj: p2},
	}, sort(out))

	// WHEN a new process with no connections is created
	// THEN it should be also reported
	// (use case: we want to later match by executable path a client process with short-lived connections)
	out = testutil.ReadChannel(t, accounterOutput, testTimeout)
	assert.Equal(t, []Event[processAttrs]{
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

func TestProcessNotReady(t *testing.T) {
	// mocking a fake listProcesses method
	p1 := processAttrs{pid: 1, openPorts: []uint32{3030, 3031}}
	p2 := processAttrs{pid: 2, openPorts: []uint32{123}}
	p3 := processAttrs{pid: 3, openPorts: []uint32{456}}
	p4 := processAttrs{pid: 4, openPorts: []uint32{789}}
	p5 := processAttrs{pid: 10}

	acc := pollAccounter{
		interval: time.Microsecond,
		cfg:      &beyla.Config{},
		pidPorts: map[pidPort]processAttrs{},
		listProcesses: func(bool) (map[PID]processAttrs, error) {
			return map[PID]processAttrs{p1.pid: p1, p5.pid: p5, p2.pid: p2, p3.pid: p3, p4.pid: p4}, nil
		},
		executableReady: func(pid PID) (string, bool) {
			return "", pid >= 3
		},
		loadBPFWatcher: func(context.Context, *beyla.Config, chan<- watcher.Event) error {
			return nil
		},
		loadBPFLogger: func(context.Context, *beyla.Config) error {
			return nil
		},
	}

	procs, err := acc.listProcesses(true)
	assert.NoError(t, err)
	assert.Equal(t, 5, len(procs))
	events := acc.snapshot(procs)
	assert.Equal(t, 3, len(events))       // 2 are not ready
	assert.Equal(t, 3, len(acc.pids))     // this should equal the first invocation of snapshot
	assert.Equal(t, 2, len(acc.pidPorts)) // only 2 ports opened, p5 has no ports

	eventsNext := acc.snapshot(procs)
	assert.Equal(t, 0, len(eventsNext)) // 0 new events
	assert.Equal(t, 3, len(acc.pids))   // this should equal the first invocation of snapshot, no changes

	acc.executableReady = func(pid PID) (string, bool) { // we change so that pid=1 becomes ready
		return "", pid != 2
	}

	eventsNextNext := acc.snapshot(procs)
	assert.Equal(t, 1, len(eventsNextNext)) // 1 net new event
	assert.Equal(t, 4, len(acc.pids))       // this should increase by one since we have one more PID we are caching now
	assert.Equal(t, 4, len(acc.pidPorts))   // this is now 4 because pid=1 has 2 port mappings
}

func TestPortsFetchRequired(t *testing.T) {
	userConfig := bytes.NewBufferString("channel_buffer_len: 33")
	require.NoError(t, os.Setenv("BEYLA_OPEN_PORT", "8080-8089"))

	cfg, err := beyla.LoadConfig(userConfig)
	require.NoError(t, err)

	channelReturner := make(chan chan<- watcher.Event)

	ctx, cancel := context.WithCancel(context.Background())

	acc := pollAccounter{
		cfg:      cfg,
		interval: time.Hour, // don't let the inner loop mess with our test
		pidPorts: map[pidPort]processAttrs{},
		listProcesses: func(bool) (map[PID]processAttrs, error) {
			return nil, nil
		},
		executableReady: func(_ PID) (string, bool) {
			return "", true
		},
		loadBPFWatcher: func(_ context.Context, _ *beyla.Config, events chan<- watcher.Event) error {
			channelReturner <- events
			return nil
		},
		loadBPFLogger: func(context.Context, *beyla.Config) error {
			return nil
		},
		stateMux:          sync.Mutex{},
		bpfWatcherEnabled: false,
		fetchPorts:        true,
		findingCriteria:   FindingCriteria(cfg),
		output:            msg.NewQueue[[]Event[processAttrs]](msg.ChannelBufferLen(1)),
	}

	accounterExited := make(chan struct{})
	go func() {
		acc.run(ctx)
		close(accounterExited)
	}()

	eventsChan := testutil.ReadChannel(t, channelReturner, testTimeout)

	assert.True(t, acc.portFetchRequired()) // initial state means poll all ports until we are ready to look for binds in bpf
	eventsChan <- watcher.Event{Type: watcher.NewPort}
	assert.True(t, acc.portFetchRequired())
	eventsChan <- watcher.Event{Type: watcher.Ready}
	assert.True(t, acc.portFetchRequired()) // we must see it true one more time
	assert.EventuallyWithTf(t, func(c *assert.CollectT) {
		assert.False(c, acc.portFetchRequired()) // eventually we'll see this being false
	}, 5*time.Second, 100*time.Millisecond, "eventsChan was never set")
	assert.False(t, acc.portFetchRequired()) // another false after that

	// we send new port watcher event which matches the port range
	eventsChan <- watcher.Event{Type: watcher.NewPort, Payload: 8080}
	assert.EventuallyWithTf(t, func(c *assert.CollectT) {
		assert.True(c, acc.portFetchRequired()) // eventually we'll see this being true
	}, 5*time.Second, 100*time.Millisecond, "eventsChan was never set")
	assert.False(t, acc.portFetchRequired()) // once we see it true, next time it's false

	// we send port that's not in our port range
	eventsChan <- watcher.Event{Type: watcher.NewPort, Payload: 8090}
	// 5 seconds should be enough to have the channel send something
	for i := 0; i < 5; i++ {
		assert.False(t, acc.portFetchRequired()) // once we see it true, next time it's false
		time.Sleep(1 * time.Second)
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
func sort(events []Event[processAttrs]) []Event[processAttrs] {
	slices.SortFunc(events, func(a, b Event[processAttrs]) int {
		return int(a.Obj.pid) - int(b.Obj.pid)
	})
	return events
}

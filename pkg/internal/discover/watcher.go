package discover

import (
	"context"
	"log/slog"
	"time"

	"github.com/mariomac/pipes/pkg/node"
	"github.com/shirou/gopsutil/process"
)

const (
	defaultPollInterval = 5 * time.Second
)

// Watcher polls every PollInterval for new processes and forwards either new processes
// or deleted processes
type Watcher struct {
	Ctx          context.Context
	PollInterval time.Duration
}

type WatchEventType int

const (
	EventCreated = WatchEventType(iota)
	EventDeleted
)

type Event[T any] struct {
	Type WatchEventType
	Obj  T
}

func WatcherProvider(w Watcher) (node.StartFunc[[]Event[*process.Process]], error) {
	acc := pollAccounter{
		ctx:           w.Ctx,
		interval:      w.PollInterval,
		pids:          map[int32]*process.Process{},
		listProcesses: process.Processes,
	}
	if acc.interval == 0 {
		acc.interval = defaultPollInterval
	}
	return acc.Run, nil
}

// TODO: replace a poller by a listener, or allow users trying between both
type pollAccounter struct {
	ctx      context.Context
	interval time.Duration
	pids     map[int32]*process.Process
	// injectable function
	listProcesses func() ([]*process.Process, error)
}

func (pa *pollAccounter) Run(out chan<- []Event[*process.Process]) {
	log := slog.With("component", "discover.Watcher", "interval", pa.interval)
	for {
		procs, err := pa.listProcesses()
		if err != nil {
			log.Warn("can't get system processes", "error", err)
		} else {
			if events := pa.snapshot(procs); len(events) > 0 {
				log.Debug("new process watching events", "len", len(events))
				out <- events
			}
		}
		select {
		case <-pa.ctx.Done():
			log.Debug("context canceled. Exiting")
			return
		case <-time.After(pa.interval):
			// poll event starting again
		}
	}
}

// snapshot compares the current processes with the status of the previous poll
// and forwards a list of process creation/deletion events
func (pa *pollAccounter) snapshot(procs []*process.Process) []Event[*process.Process] {
	var events []Event[*process.Process]
	currentPids := make(map[int32]*process.Process, len(procs))
	// notify processes that are new
	for _, p := range procs {
		currentPids[p.Pid] = p
		if _, ok := pa.pids[p.Pid]; !ok {
			events = append(events, Event[*process.Process]{Type: EventCreated, Obj: p})
		}
	}
	// notify processes that are removed
	for pid, p := range pa.pids {
		if _, ok := currentPids[pid]; !ok {
			events = append(events, Event[*process.Process]{Type: EventDeleted, Obj: p})
		}
	}
	pa.pids = currentPids
	return events
}

package process

import (
	"context"
	"log/slog"
	"time"

	"github.com/mariomac/pipes/pkg/graph/stage"
	"github.com/mariomac/pipes/pkg/node"
	"github.com/shirou/gopsutil/process"
)

const (
	defaultPollInterval = 5 * time.Second
)

type Watcher struct {
	PollInterval time.Duration
}

type WatchEvenType int

const (
	EventCreated = WatchEvenType(iota)
	EventDeleted
)

type WatchEvent struct {
	Type    WatchEvenType
	Process *process.Process
}

func WatcherProvider(ctx context.Context) stage.StartProvider[Watcher, []WatchEvent] {
	return func(w Watcher) (node.StartFunc[[]WatchEvent], error) {
		acc := pollAccounter{
			ctx:           ctx,
			interval:      w.PollInterval,
			pids:          map[int32]*process.Process{},
			listProcesses: process.Processes,
		}
		if acc.interval == 0 {
			acc.interval = defaultPollInterval
		}
		return acc.Run, nil
	}
}

// TODO: replace a poller by a listener, or allow users trying between both
type pollAccounter struct {
	ctx      context.Context
	interval time.Duration
	pids     map[int32]*process.Process
	// injectable function
	listProcesses func() ([]*process.Process, error)
}

func (pa *pollAccounter) Run(out chan<- []WatchEvent) {
	log := slog.With("component", "process.Watcher", "interval", pa.interval)
	for {
		procs, err := pa.listProcesses()
		if err != nil {
			log.Warn("can't get system processes", "error", err)
		} else {
			if events := pa.snapshot(procs); len(events) > 0 {
				log.Debug("sending events", "len", len(events))
				out <- events
			}
		}
		select {
		case <-pa.ctx.Done():
			log.Debug("context canceled. Exiting")
			return
		case <-time.After(pa.interval):
			log.Debug("poll event starting again")
		}
	}
}

func (pa *pollAccounter) snapshot(procs []*process.Process) []WatchEvent {
	var events []WatchEvent
	currentPids := make(map[int32]*process.Process, len(procs))
	// notify processes that are new
	for _, p := range procs {
		currentPids[p.Pid] = p
		if _, ok := pa.pids[p.Pid]; !ok {
			events = append(events, WatchEvent{Type: EventCreated, Process: p})
		}
	}
	// notify processes that are removed
	for pid, p := range pa.pids {
		if _, ok := currentPids[pid]; !ok {
			events = append(events, WatchEvent{Type: EventDeleted, Process: p})
		}
	}
	pa.pids = currentPids
	return events
}

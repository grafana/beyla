package discover

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/mariomac/pipes/pkg/node"
	"github.com/shirou/gopsutil/net"
	"github.com/shirou/gopsutil/process"
)

const (
	defaultPollInterval = 5 * time.Second
	ephemeralPortMin    = 32768
)

// Watcher polls every PollInterval for new processes and forwards either new or deleted process PIDs
// as well as PIDs from processes that setup a new connection
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

type PID int32

type processPorts struct {
	pid       PID
	openPorts []uint32
}

func wplog() *slog.Logger {
	return slog.With("component", "discover.Watcher")
}

func WatcherProvider(w Watcher) (node.StartFunc[[]Event[processPorts]], error) {
	acc := pollAccounter{
		ctx:           w.Ctx,
		interval:      w.PollInterval,
		pids:          map[PID]processPorts{},
		pidPorts:      map[pidPort]processPorts{},
		listProcesses: fetchProcessPorts,
	}
	if acc.interval == 0 {
		acc.interval = defaultPollInterval
	}
	return acc.Run, nil
}

// pidPort associates a PID with its open port
type pidPort struct {
	Pid  PID
	Port uint32
}

// TODO: combine the poller with an eBPF listener (poll at start and e.g. every 30 seconds, and keep listening eBPF in background)
type pollAccounter struct {
	ctx      context.Context
	interval time.Duration
	// last polled process:ports accessible by its pid
	pids map[PID]processPorts
	// last polled process:ports accessible by a combination of pid/connection port
	// same process might appear several times
	pidPorts map[pidPort]processPorts
	// injectable function
	listProcesses func() (map[PID]processPorts, error)
}

func (pa *pollAccounter) Run(out chan<- []Event[processPorts]) {
	log := slog.With("component", "discover.Watcher", "interval", pa.interval)
	for {
		procs, err := pa.listProcesses()
		if err != nil {
			log.Warn("can't get system processes", "error", err)
		} else {
			if events := pa.snapshot(procs); len(events) > 0 {
				log.Debug("new process watching events", "events", events)
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
func (pa *pollAccounter) snapshot(fetchedProcs map[PID]processPorts) []Event[processPorts] {
	var events []Event[processPorts]
	currentPidPorts := make(map[pidPort]processPorts, len(fetchedProcs))
	reportedProcs := map[PID]struct{}{}
	// notify processes that are new, or already existed but have a new connection
	for pid, proc := range fetchedProcs {
		// if the process does not have open ports, we might still notify it
		// for example, if it's a client with ephemeral connections, which might be later matched by executable name
		if len(proc.openPorts) == 0 {
			if pa.checkNewProcessNotification(pid, reportedProcs) {
				events = append(events, Event[processPorts]{Type: EventCreated, Obj: proc})
			}
		} else {
			for _, port := range proc.openPorts {
				if pa.checkNewProcessConnectionNotification(proc, port, currentPidPorts, reportedProcs) {
					events = append(events, Event[processPorts]{Type: EventCreated, Obj: proc})
					// skip checking new connections for that process
					continue
				}
			}
		}
	}
	// notify processes that are removed
	for pid, proc := range pa.pids {
		if _, ok := fetchedProcs[pid]; !ok {
			events = append(events, Event[processPorts]{Type: EventDeleted, Obj: proc})
		}
	}
	pa.pids = fetchedProcs
	pa.pidPorts = currentPidPorts
	return events
}

func (pa *pollAccounter) checkNewProcessConnectionNotification(
	proc processPorts,
	port uint32,
	currentPidPorts map[pidPort]processPorts,
	reportedProcs map[PID]struct{},
) bool {
	pp := pidPort{Pid: proc.pid, Port: port}
	currentPidPorts[pp] = proc
	// the connection existed before iff we already had registered this pid/port pair
	_, existingConnection := pa.pidPorts[pp]
	// the proc existed before iff we already had registered this pid
	_, existingProcess := pa.pids[proc.pid]
	// we notify the creation either if the connection and the process is new...
	if !existingConnection || !existingProcess {
		// ...also if we haven't already reported the process in the last "snapshot" invocation
		if _, ok := reportedProcs[pp.Pid]; !ok {
			// avoid notifying multiple times the same process if it has multiple connections
			reportedProcs[proc.pid] = struct{}{}
			return true
		}
	}
	return false
}

// checkNewProcessNotification returns true if the process has to be notified as new.
// It accordingly updates the reportedProcs map
func (pa *pollAccounter) checkNewProcessNotification(pid PID, reportedProcs map[PID]struct{}) bool {
	// the proc existed before iff we already had registered this pid from a previous snapshot
	if _, existingProcess := pa.pids[pid]; !existingProcess {
		// ...also if we haven't already reported the process in the last "snapshot" invocation
		if _, ok := reportedProcs[pid]; !ok {
			// avoid notifying multiple times the same process if it has multiple connections
			reportedProcs[pid] = struct{}{}
			return true
		}
	}
	return false
}

// fetchProcessConnections returns a map with the PIDs of all the running processes as a key,
// and the open ports for the given process as a value
func fetchProcessPorts() (map[PID]processPorts, error) {
	log := wplog()
	processes := map[PID]processPorts{}
	pids, err := process.Pids()
	if err != nil {
		return nil, fmt.Errorf("can't get processes: %w", err)
	}
	for _, pid := range pids {
		conns, err := net.ConnectionsPid("inet", pid)
		if err != nil {
			log.Debug("can't get connections for process. Skipping", "pid", pid, "error", err)
			continue
		}
		var openPorts []uint32
		for _, conn := range conns {
			if conn.Laddr.Port < ephemeralPortMin {
				openPorts = append(openPorts, conn.Laddr.Port)
			}
		}
		processes[PID(pid)] = processPorts{pid: PID(pid), openPorts: openPorts}
	}
	return processes, nil
}

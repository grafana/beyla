package discover

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/mariomac/pipes/pkg/node"
	"github.com/shirou/gopsutil/net"
	"github.com/shirou/gopsutil/process"

	"github.com/grafana/beyla/pkg/internal/discover/services"
)

const (
	defaultPollInterval = 5 * time.Second
)

// Watcher polls every PollInterval for new processes and forwards either new or deleted processes
// as well as process that setup a new connection
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

func wplog() *slog.Logger {
	return slog.With("component", "discover.Watcher")
}

func WatcherProvider(w Watcher) (node.StartFunc[[]Event[*services.ProcessInfo]], error) {
	acc := pollAccounter{
		ctx:           w.Ctx,
		interval:      w.PollInterval,
		pids:          map[int32]*services.ProcessInfo{},
		pidPorts:      map[pidPort]*services.ProcessInfo{},
		listProcesses: connectedProcesses,
	}
	if acc.interval == 0 {
		acc.interval = defaultPollInterval
	}
	return acc.Run, nil
}

// pidPort associates a PID with its open port
type pidPort struct {
	Pid  int32
	Port uint32
}

// TODO: combine the poller with an eBPF listener (poll at start and e.g. every 30 seconds, and keep listening eBPF in background)
type pollAccounter struct {
	ctx      context.Context
	interval time.Duration
	// last polled processes accessible by its pid
	pids map[int32]*services.ProcessInfo
	// last polled processes accesible by a combination of pid/connection port
	// same process might appear several times
	pidPorts map[pidPort]*services.ProcessInfo
	// injectable function
	listProcesses func() (map[int32]*services.ProcessInfo, error)
}

func (pa *pollAccounter) Run(out chan<- []Event[*services.ProcessInfo]) {
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
func (pa *pollAccounter) snapshot(fetchedProcs map[int32]*services.ProcessInfo) []Event[*services.ProcessInfo] {
	var events []Event[*services.ProcessInfo]
	currentPidPorts := make(map[pidPort]*services.ProcessInfo, len(fetchedProcs))
	reportedProcs := map[int32]struct{}{}
	// notify processes that are new, or already existed but have a new connection
	for _, proc := range fetchedProcs {
		// if the process does not have open ports, we might still notify it
		// for example, if it's a client with ephemeral connections, which might be later matched by executable name
		if len(proc.OpenPorts) == 0 {
			if ev, ok := pa.checkProcessNotification(proc, reportedProcs); ok {
				events = append(events, ev)
			}
		} else {
			for _, port := range proc.OpenPorts {
				if ev, ok := pa.checkProcessConnectionNotification(proc, port, currentPidPorts, reportedProcs); ok {
					events = append(events, ev)
					continue
				}
			}
		}
	}
	// notify processes that are removed
	for pp, proc := range pa.pids {
		if _, ok := fetchedProcs[pp]; !ok {
			events = append(events, Event[*services.ProcessInfo]{Type: EventDeleted, Obj: proc})
		}
	}
	pa.pids = fetchedProcs
	pa.pidPorts = currentPidPorts
	return events
}

func (pa *pollAccounter) checkProcessConnectionNotification(
	proc *services.ProcessInfo,
	port uint32,
	currentPidPorts map[pidPort]*services.ProcessInfo,
	reportedProcs map[int32]struct{},
) (Event[*services.ProcessInfo], bool) {
	pp := pidPort{Pid: proc.Pid, Port: port}
	currentPidPorts[pp] = proc
	// the connection existed before iff we already had registered this pid/port pair
	_, existingConnection := pa.pidPorts[pp]
	// the proc existed before iff we already had registered this pid
	_, existingProcess := pa.pids[proc.Pid]
	// we notify the creation either if the connection and the process is new...
	if !existingConnection || !existingProcess {
		// ...also if we haven't already reported the process in the last "snapshot" invocation
		if _, ok := reportedProcs[pp.Pid]; !ok {
			// avoid notifying multiple times the same process if it has multiple connections
			reportedProcs[pp.Pid] = struct{}{}
			return Event[*services.ProcessInfo]{Type: EventCreated, Obj: proc}, true
		}
	}
	return Event[*services.ProcessInfo]{}, false
}

func (pa *pollAccounter) checkProcessNotification(
	proc *services.ProcessInfo,
	reportedProcs map[int32]struct{},
) (Event[*services.ProcessInfo], bool) {
	// the proc existed before iff we already had registered this pid from a previous snapshot
	if _, existingProcess := pa.pids[proc.Pid]; !existingProcess {
		// ...also if we haven't already reported the process in the last "snapshot" invocation
		if _, ok := reportedProcs[proc.Pid]; !ok {
			// avoid notifying multiple times the same process if it has multiple connections
			reportedProcs[proc.Pid] = struct{}{}
			return Event[*services.ProcessInfo]{Type: EventCreated, Obj: proc}, true
		}
	}
	return Event[*services.ProcessInfo]{}, false
}

func connectedProcesses() (map[int32]*services.ProcessInfo, error) {
	processes := map[int32]*services.ProcessInfo{}
	// In containerized environments, processess might be visible through either
	// the shared network or the shared PID namespace, so we fetch them from both sources
	if err := fetchProcesses(processes); err != nil {
		return nil, err
	}
	if err := fetchConnections(processes); err != nil {
		return nil, err
	}
	return processes, nil
}

func fetchProcesses(processes map[int32]*services.ProcessInfo) error {
	procs, err := process.Processes()
	if err != nil {
		return fmt.Errorf("can't get processes: %w", err)
	}
	for _, proc := range procs {
		conns, _ := proc.Connections()
		if len(conns) > 0 {
			if pi, err := processInfo(proc); err != nil {
				wplog().Warn("can't get process information", "pid", proc.Pid, "error", err)
			} else {
				for _, conn := range conns {
					pi.OpenPorts = append(pi.OpenPorts, conn.Laddr.Port)
				}
				processes[proc.Pid] = pi
			}
		}
	}
	return nil
}

func fetchConnections(processes map[int32]*services.ProcessInfo) error {
	conns, err := net.Connections("inet")
	if err != nil {
		return fmt.Errorf("can't get network connections: %w", err)
	}
	for i := range conns {
		conn := &conns[i]
		if conn.Pid == 0 {
			continue
		}
		proc, ok := processes[conn.Pid]
		if !ok {
			if proc, err = processFromConnection(conn); err != nil {
				wplog().Warn("can't read process information", "pid", conn.Pid, "err", err)
				continue
			}
			processes[conn.Pid] = proc
		}
		proc.OpenPorts = append(proc.OpenPorts, conn.Laddr.Port)
	}
	return nil
}

func processFromConnection(conn *net.ConnectionStat) (*services.ProcessInfo, error) {
	proc, err := process.NewProcess(conn.Pid)
	if err != nil {
		return nil, err
	}
	return processInfo(proc)
}

func processInfo(proc *process.Process) (*services.ProcessInfo, error) {
	ppid, _ := proc.Ppid()
	exePath, err := proc.Exe()
	if err != nil {
		if err := tryAccessPid(proc.Pid); err != nil {
			return nil, fmt.Errorf("can't read /proc/<pid>/fd information: %w", err)
		}
		// this might happen if you query from the port a service that does not have executable path.
		// Since this value is just for attributing, we set a default placeholder
		exePath = "unknown"
	}
	return &services.ProcessInfo{
		Pid:     proc.Pid,
		PPid:    ppid,
		ExePath: exePath,
	}, nil
}

func tryAccessPid(pid int32) error {
	// TODO: allow overriding proc root
	dir := fmt.Sprintf("/proc/%d/fd", pid)
	_, err := os.Open(dir)
	return err
}

package discover

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/internal/ebpf"
	"github.com/grafana/beyla/v2/pkg/internal/ebpf/logger"
	"github.com/grafana/beyla/v2/pkg/internal/ebpf/watcher"
	"github.com/grafana/beyla/v2/pkg/pipe/msg"
	"github.com/grafana/beyla/v2/pkg/pipe/swarm"
	"github.com/grafana/beyla/v2/pkg/services"
)

const (
	defaultPollInterval = 5 * time.Second
)

type WatchEventType int

const (
	EventCreated = WatchEventType(iota)
	EventDeleted
	EventInstanceDeleted
)

type Event[T any] struct {
	Type WatchEventType
	Obj  T
}

type PID int32

type processAttrs struct {
	pid            PID
	openPorts      []uint32
	metadata       map[string]string
	podLabels      map[string]string
	podAnnotations map[string]string
	// Name of the process
	processName string
	// Status of the process
	processStatus string
	// Age of the process
	processAge time.Duration
}

func wplog() *slog.Logger {
	return slog.With("component", "discover.ProcessWatcher")
}

// ProcessWatcherFunc polls every PollInterval for new processes and forwards either new or deleted process PIDs
// as well as PIDs from processes that setup a new connection
func ProcessWatcherFunc(cfg *beyla.Config, output *msg.Queue[[]Event[processAttrs]]) swarm.RunFunc {
	acc := pollAccounter{
		cfg:               cfg,
		output:            output,
		interval:          cfg.Discovery.PollInterval,
		pids:              map[PID]processAttrs{},
		pidPorts:          map[pidPort]processAttrs{},
		listProcesses:     fetchProcessPorts,
		executableReady:   executableReady,
		loadBPFWatcher:    loadBPFWatcher,
		loadBPFLogger:     loadBPFLogger,
		fetchPorts:        true,  // must be true until we've activated the bpf watcher component
		bpfWatcherEnabled: false, // async set by listening on the bpfWatchEvents channel
		stateMux:          sync.Mutex{},
		findingCriteria:   FindingCriteria(cfg),
	}
	if acc.interval == 0 {
		acc.interval = defaultPollInterval
	}
	return acc.run
}

// pidPort associates a PID with its open port
type pidPort struct {
	Pid  PID
	Port uint32
}

// TODO: combine the poller with an eBPF listener (poll at start and e.g. every 30 seconds, and keep listening eBPF in background)
// ^ This is partially done, although it's not fully async, we only use the info to reduce the overhead of port scanning.
type pollAccounter struct {
	cfg      *beyla.Config
	interval time.Duration
	// last polled process:ports accessible by its pid
	pids map[PID]processAttrs
	// last polled process:ports accessible by a combination of pid/connection port
	// same process might appear several times
	pidPorts map[pidPort]processAttrs
	// injectable function
	listProcesses func(bool, time.Duration) (map[PID]processAttrs, error)
	// injectable function
	executableReady func(PID) (string, bool)
	// injectable function to load the bpf program
	loadBPFWatcher func(ctx context.Context, cfg *beyla.Config, events chan<- watcher.Event) error
	loadBPFLogger  func(ctx context.Context, cfg *beyla.Config) error
	// we use these to ensure we poll for the open ports effectively
	stateMux          sync.Mutex
	bpfWatcherEnabled bool
	fetchPorts        bool
	findingCriteria   []services.Selector
	output            *msg.Queue[[]Event[processAttrs]]
}

func (pa *pollAccounter) run(ctx context.Context) {
	defer pa.output.Close()

	log := slog.With("component", "discover.ProcessWatcher", "interval", pa.interval)

	bpfWatchEvents := make(chan watcher.Event, 100)
	if err := pa.loadBPFWatcher(ctx, pa.cfg, bpfWatchEvents); err != nil {
		log.Error("Unable to load eBPF watcher for process events", "error", err)
		// will stop pipeline in cascade
		return
	}

	if pa.cfg.EBPF.BpfDebug {
		if err := pa.loadBPFLogger(ctx, pa.cfg); err != nil {
			log.Error("Unable to load eBPF logger for process events", "error", err)
			// keep running without logs
		}
	}

	go pa.watchForProcessEvents(ctx, log, bpfWatchEvents)

	for {
		procs, err := pa.listProcesses(pa.portFetchRequired(), pa.cfg.Discovery.MinProcessAge)
		if err != nil {
			log.Warn("can't get system processes", "error", err)
		} else {
			if events := pa.snapshot(procs); len(events) > 0 {
				log.Debug("new process watching events", "events", events)
				pa.output.Send(events)
			}
		}
		select {
		case <-ctx.Done():
			log.Debug("context canceled. Exiting")
			return
		case <-time.After(pa.interval):
			// poll event starting again
		}
	}
}

func (pa *pollAccounter) bpfWatcherIsReady() {
	pa.stateMux.Lock()
	defer pa.stateMux.Unlock()
	pa.bpfWatcherEnabled = true
}

func (pa *pollAccounter) refetchPorts() {
	pa.stateMux.Lock()
	defer pa.stateMux.Unlock()
	pa.fetchPorts = true
}

func (pa *pollAccounter) portFetchRequired() bool {
	pa.stateMux.Lock()
	defer pa.stateMux.Unlock()

	if !pa.bpfWatcherEnabled {
		return true
	}

	ret := pa.fetchPorts
	pa.fetchPorts = false

	return ret
}

func portOfInterest(criteria []services.Selector, port int) bool {
	for _, cr := range criteria {
		if cr.GetOpenPorts().Matches(port) {
			return true
		}
	}
	return false
}

func (pa *pollAccounter) watchForProcessEvents(ctx context.Context, log *slog.Logger, events <-chan watcher.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-events:
			switch e.Type {
			case watcher.Ready:
				pa.bpfWatcherIsReady()
			case watcher.NewPort:
				port := int(e.Payload)
				if pa.cfg.Port.Matches(port) || portOfInterest(pa.findingCriteria, port) {
					pa.refetchPorts()
				}
			default:
				log.Warn("Unknown ebpf process watch event", "type", e.Type)
			}
		}
	}
}

// snapshot compares the current processes with the status of the previous poll
// and forwards a list of process creation/deletion events
func (pa *pollAccounter) snapshot(fetchedProcs map[PID]processAttrs) []Event[processAttrs] {
	log := wplog()
	var events []Event[processAttrs]
	currentPidPorts := make(map[pidPort]processAttrs, len(fetchedProcs))
	reportedProcs := map[PID]struct{}{}
	notReadyProcs := map[PID]struct{}{}
	// notify processes that are new, or already existed but have a new connection
	for pid, proc := range fetchedProcs {
		// if the process does not have open ports, we might still notify it
		// for example, if it's a client with ephemeral connections, which might be later matched by executable name
		if len(proc.openPorts) == 0 {
			if pa.checkNewProcessNotification(pid, reportedProcs, notReadyProcs) {
				events = append(events, Event[processAttrs]{Type: EventCreated, Obj: proc})
				log.Info("Process added", "pid", pid, "name", proc.processName, "status", proc.processStatus, "age", proc.processAge.Round(time.Second))
			}
		} else {
			for _, port := range proc.openPorts {
				if pa.checkNewProcessConnectionNotification(proc, port, currentPidPorts, reportedProcs, notReadyProcs) {
					events = append(events, Event[processAttrs]{Type: EventCreated, Obj: proc})
					log.Info("Process added", "pid", pid, "name", proc.processName, "status", proc.processStatus, "age", proc.processAge.Round(time.Second), "port", port)
					// skip checking new connections for that process
					continue
				}
			}
		}
	}
	// notify processes that are removed
	for pid, proc := range pa.pids {
		if _, ok := fetchedProcs[pid]; !ok {
			events = append(events, Event[processAttrs]{Type: EventDeleted, Obj: proc})
			log.Info("Process removed", "pid", pid, "name", proc.processName, "status", proc.processStatus, "age", proc.processAge.Round(time.Second))
		}
	}

	currentProcs := maps.Clone(fetchedProcs)

	// Remove the processes that are not fully instantiated from the list before
	// caching the current pids in the snapshot.
	for pid := range notReadyProcs {
		delete(currentProcs, pid)
	}

	for pp := range currentPidPorts {
		if _, ok := notReadyProcs[pp.Pid]; ok {
			delete(currentPidPorts, pp)
		}
	}

	pa.pids = currentProcs
	pa.pidPorts = currentPidPorts
	return events
}

func executableReady(pid PID) (string, bool) {
	proc, err := process.NewProcess(int32(pid))
	if err != nil {
		return "", false
	}
	exePath, err := proc.Exe()

	if err != nil {
		return exePath, errors.Is(err, os.ErrNotExist)
	}

	return exePath, exePath != "/"
}

func (pa *pollAccounter) checkNewProcessConnectionNotification(
	proc processAttrs,
	port uint32,
	currentPidPorts map[pidPort]processAttrs,
	reportedProcs, notReadyProcs map[PID]struct{},
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
			exec, ok := pa.executableReady(pp.Pid)
			if ok {
				wplog().Debug("Executable ready", "path", exec, "pid", pp.Pid, "port", port)
				return true
			}
			notReadyProcs[pp.Pid] = struct{}{}
			wplog().Debug("Executable not ready", "path", exec, "pid", pp.Pid, "port", port)
		}
	}
	return false
}

// checkNewProcessNotification returns true if the process has to be notified as new.
// It accordingly updates the reportedProcs map
func (pa *pollAccounter) checkNewProcessNotification(pid PID, reportedProcs, notReadyProcs map[PID]struct{}) bool {
	// the proc existed before iff we already had registered this pid from a previous snapshot
	if _, existingProcess := pa.pids[pid]; !existingProcess {
		// ...also if we haven't already reported the process in the last "snapshot" invocation
		if _, ok := reportedProcs[pid]; !ok {
			// avoid notifying multiple times the same process if it has multiple connections
			reportedProcs[pid] = struct{}{}
			exec, ok := pa.executableReady(pid)
			if ok {
				wplog().Debug("Executable ready", "path", exec, "pid", pid)
				return true
			}
			notReadyProcs[pid] = struct{}{}
			wplog().Debug("Executable not ready", "path", exec, "pid", pid)
		}
	}
	return false
}

// fetchProcessConnections returns a map with the PIDs of all the running processes as a key,
// and the open ports for the given process as a value
func fetchProcessPorts(scanPorts bool, minProcessAge time.Duration) (map[PID]processAttrs, error) {
	log := wplog()
	processes := map[PID]processAttrs{}
	pids, err := process.Pids()
	if err != nil {
		return nil, fmt.Errorf("can't get processes: %w", err)
	}

	for _, pid := range pids {
		proc, err := process.NewProcess(int32(pid))
		if err != nil {
			continue
		}
		createTime, err := proc.CreateTime()
		if err != nil {
			continue
		}
		// Print the process name
		processName, err := proc.Name()
		if err != nil {
			continue
		}
		// Process status
		status, err := proc.Status()
		if err != nil {
			continue
		}

		startTime := time.UnixMilli(createTime)
		duration := time.Since(startTime)

		// Check if the process is running for more than the minProcessAge
		if duration < minProcessAge {
			log.Info("Skipping process", "pid", pid, "name", processName, "status", status, "age", duration.Round(time.Microsecond))
			continue
		}
		if !scanPorts {
			processes[PID(pid)] = processAttrs{pid: PID(pid), openPorts: []uint32{}, processName: processName, processStatus: status[0], processAge: duration}
			continue
		}
		conns, err := net.ConnectionsPid("inet", pid)
		if err != nil {
			log.Debug("can't get connections for process. Skipping", "pid", pid, "error", err)
			continue
		}
		var openPorts []uint32
		// TODO: Cap the size of this array, leaking client ephemeral ports will cause this to grow very long
		for _, conn := range conns {
			openPorts = append(openPorts, conn.Laddr.Port)
		}
		processes[PID(pid)] = processAttrs{pid: PID(pid), openPorts: openPorts, processName: processName, processStatus: status[0], processAge: duration}
	}
	return processes, nil
}

func loadBPFWatcher(ctx context.Context, cfg *beyla.Config, events chan<- watcher.Event) error {
	wt := watcher.New(cfg, events)
	return ebpf.RunUtilityTracer(ctx, wt)
}

func loadBPFLogger(ctx context.Context, cfg *beyla.Config) error {
	wt := logger.New(cfg)
	return ebpf.RunUtilityTracer(ctx, wt)
}

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/tklauser/go-sysconf"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/logger"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/watcher"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

const (
	defaultPollInterval = 5 * time.Second
	emptyDuration       = time.Duration(0)
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

type ProcessAttrs struct {
	pid            PID
	openPorts      []uint32
	metadata       map[string]string
	podLabels      map[string]string
	podAnnotations map[string]string
	processAge     time.Duration
}

func wplog() *slog.Logger {
	return slog.With("component", "discover.ProcessWatcher")
}

// ProcessWatcherFunc polls every PollInterval for new processes and forwards either new or deleted process PIDs
// as well as PIDs from processes that setup a new connection
func ProcessWatcherFunc(cfg *obi.Config, ebpfContext *ebpfcommon.EBPFEventContext, output *msg.Queue[[]Event[ProcessAttrs]]) swarm.RunFunc {
	acc := pollAccounter{
		cfg:               cfg,
		output:            output,
		interval:          cfg.Discovery.PollInterval,
		pids:              map[PID]ProcessAttrs{},
		pidPorts:          map[pidPort]ProcessAttrs{},
		listProcesses:     fetchProcessPorts,
		executableReady:   executableReady,
		loadBPFWatcher:    loadBPFWatcher,
		loadBPFLogger:     loadBPFLogger,
		fetchPorts:        true,  // must be true until we've activated the bpf watcher component
		bpfWatcherEnabled: false, // async set by listening on the bpfWatchEvents channel
		stateMux:          sync.Mutex{},
		findingCriteria:   FindingCriteria(cfg),
		ebpfContext:       ebpfContext,
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
	cfg      *obi.Config
	interval time.Duration
	// last polled process:ports accessible by its pid
	pids map[PID]ProcessAttrs
	// last polled process:ports accessible by a combination of pid/connection port
	// same process might appear several times
	pidPorts map[pidPort]ProcessAttrs
	// injectable function
	listProcesses func(bool) (map[PID]ProcessAttrs, error)
	// injectable function
	executableReady func(PID) (string, bool)
	// injectable function to load the bpf program
	loadBPFWatcher func(ctx context.Context, ebpfContext *ebpfcommon.EBPFEventContext, cfg *obi.Config, events chan<- watcher.Event) error
	loadBPFLogger  func(ctx context.Context, ebpfContext *ebpfcommon.EBPFEventContext, cfg *obi.Config) error
	// we use these to ensure we poll for the open ports effectively
	stateMux          sync.Mutex
	bpfWatcherEnabled bool
	fetchPorts        bool
	findingCriteria   []services.Selector
	output            *msg.Queue[[]Event[ProcessAttrs]]
	ebpfContext       *ebpfcommon.EBPFEventContext
}

func (pa *pollAccounter) run(ctx context.Context) {
	defer pa.output.Close()

	log := slog.With("component", "discover.ProcessWatcher", "interval", pa.interval)

	bpfWatchEvents := make(chan watcher.Event, 100)
	if err := pa.loadBPFWatcher(ctx, pa.ebpfContext, pa.cfg, bpfWatchEvents); err != nil {
		log.Error("Unable to load eBPF watcher for process events", "error", err)
		// will stop pipeline in cascade
		return
	}

	if pa.cfg.EBPF.BpfDebug {
		if err := pa.loadBPFLogger(ctx, pa.ebpfContext, pa.cfg); err != nil {
			log.Error("Unable to load eBPF logger for process events", "error", err)
			// keep running without logs
		}
	}

	go pa.watchForProcessEvents(ctx, log, bpfWatchEvents)

	for {
		procs, err := pa.listProcesses(pa.portFetchRequired())
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
	swarms.ForEachInput(ctx, events, log.Debug, func(e watcher.Event) {
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
	})
}

func (pa *pollAccounter) processTooNew(proc ProcessAttrs) bool {
	_, existingProcess := pa.pids[proc.pid]
	if existingProcess {
		return false
	}
	// if we see duration of 0, it means we need to consider this process, since it was
	// very likely forcibly scanned because of open ports event
	return proc.processAge != time.Duration(0) && (proc.processAge < pa.cfg.Discovery.MinProcessAge)
}

// snapshot compares the current processes with the status of the previous poll
// and forwards a list of process creation/deletion events
func (pa *pollAccounter) snapshot(fetchedProcs map[PID]ProcessAttrs) []Event[ProcessAttrs] {
	log := wplog()
	var events []Event[ProcessAttrs]
	currentPidPorts := make(map[pidPort]ProcessAttrs, len(fetchedProcs))
	reportedProcs := map[PID]struct{}{}
	notReadyProcs := map[PID]struct{}{}
	// notify processes that are new, or already existed but have a new connection
	for pid, proc := range fetchedProcs {
		// if the process does not have open ports, we might still notify it
		// for example, if it's a client with ephemeral connections, which might be later matched by executable name
		if len(proc.openPorts) == 0 {
			if pa.checkNewProcessNotification(pid, reportedProcs, notReadyProcs) {
				if pa.processTooNew(proc) {
					log.Debug("delaying process analysis, too soon", "pid", pid, "age", proc.processAge)
					notReadyProcs[pid] = struct{}{}
					continue
				}
				events = append(events, Event[ProcessAttrs]{Type: EventCreated, Obj: proc})
				log.Debug("process added", "pid", pid)
			}
		} else {
			for _, port := range proc.openPorts {
				if pa.checkNewProcessConnectionNotification(proc, port, currentPidPorts, reportedProcs, notReadyProcs) {
					events = append(events, Event[ProcessAttrs]{Type: EventCreated, Obj: proc})
					log.Debug("process added", "pid", pid, "port", port)
					// skip checking new connections for that process
					continue
				}
			}
		}
	}

	// notify processes that are removed
	for pid, proc := range pa.pids {
		if _, ok := fetchedProcs[pid]; !ok {
			events = append(events, Event[ProcessAttrs]{Type: EventDeleted, Obj: proc})
			log.Debug("process removed", "pid", pid)
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

	return exePath, (exePath != "/" && exePath != "")
}

func (pa *pollAccounter) checkNewProcessConnectionNotification(
	proc ProcessAttrs,
	port uint32,
	currentPidPorts map[pidPort]ProcessAttrs,
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

func makeProcessAgeFunc() func(int32) time.Duration {
	r := procStatReader{}
	return r.processAge
}

// overridden in tests
var processAgeFunc = makeProcessAgeFunc()

// see https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html
func parseProcStatField(buf string, field int) string {
	inParens := false

	// field 2 is the comm, which is deliminated by parens and can contain
	// whitespace, e.g. (foo bar) - this function accounts for that
	f := func(c rune) bool {
		if c == '(' {
			inParens = true
			return true
		}

		if inParens {
			if c == ')' {
				inParens = false
				return true
			}

			return false
		}

		return c == ' '
	}

	i := 1

	for word := range strings.FieldsFuncSeq(buf, f) {
		if i == field {
			return word
		}

		i++
	}

	return ""
}

type procStatReader struct {
	buf [4096]byte // 4KB buffer: safely fits /proc/self/stat (~52 fields * 20 chars + comm + spaces)
}

func (r *procStatReader) getProcStatField(pid int32, field int) string {
	path := fmt.Sprintf("/proc/%d/stat", pid)

	f, err := os.Open(path)
	if err != nil {
		return ""
	}

	defer f.Close()

	nbytes, err := f.Read(r.buf[:])
	if err != nil {
		return ""
	}

	return parseProcStatField(string(r.buf[:nbytes]), field)
}

func ticksToNanosecond(ticks uint64) uint64 {
	clkTck, err := sysconf.Sysconf(sysconf.SC_CLK_TCK)
	if err != nil {
		clkTck = 100 // default for Linux
	}

	return ticks * 1e9 / uint64(clkTck)
}

func nsToDuration(ns uint64) time.Duration {
	if ns > math.MaxInt64 {
		return time.Duration(math.MaxInt64) // clamp
	}

	return time.Duration(ns)
}

func (r *procStatReader) getProcStartTime(pid int32) uint64 {
	const startTimePos = 22

	val := r.getProcStatField(pid, startTimePos)

	if val == "" {
		return 0
	}

	startTimeTicks, err := strconv.ParseUint(val, 10, 64)
	if err != nil {
		return 0
	}

	return ticksToNanosecond(startTimeTicks)
}

func (r *procStatReader) processAge(pid int32) time.Duration {
	procStartTime := r.getProcStartTime(pid)

	if procStartTime == 0 {
		return emptyDuration
	}

	now := currentTime()

	if now < procStartTime {
		return emptyDuration
	}

	return nsToDuration(now - procStartTime)
}

// overridden in tests
var processPidsFunc = process.Pids

// fetchProcessConnections returns a map with the PIDs of all the running processes as a key,
// and the open ports for the given process as a value
func fetchProcessPorts(scanPorts bool) (map[PID]ProcessAttrs, error) {
	log := wplog()
	processes := map[PID]ProcessAttrs{}
	pids, err := processPidsFunc()
	if err != nil {
		return nil, fmt.Errorf("can't get processes: %w", err)
	}

	for _, pid := range pids {
		if !scanPorts {
			processes[PID(pid)] = ProcessAttrs{pid: PID(pid), openPorts: []uint32{}, processAge: processAgeFunc(pid)}
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
		processes[PID(pid)] = ProcessAttrs{pid: PID(pid), openPorts: openPorts, processAge: time.Duration(0)}
	}
	return processes, nil
}

func loadBPFWatcher(ctx context.Context, ebpfEventContext *ebpfcommon.EBPFEventContext, cfg *obi.Config, events chan<- watcher.Event) error {
	wt := watcher.New(cfg, events)
	return ebpf.RunUtilityTracer(ctx, ebpfEventContext, wt)
}

func loadBPFLogger(ctx context.Context, ebpfEventContext *ebpfcommon.EBPFEventContext, cfg *obi.Config) error {
	wt := logger.New(cfg)
	return ebpf.RunUtilityTracer(ctx, ebpfEventContext, wt)
}

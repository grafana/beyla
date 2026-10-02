package discover

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"syscall"

	"github.com/prometheus/procfs"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	obiDiscover "go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"

	"github.com/grafana/beyla/v3/pkg/internal/ebpf/surveywatcher"
	servicesextra "github.com/grafana/beyla/v3/pkg/services"
)

type surveyMatch = obiDiscover.Event[obiDiscover.ProcessMatch]

type socketProcesses interface {
	Snapshot() surveywatcher.Snapshot
	Changes() <-chan struct{}
}

type socketCandidate struct {
	startTime uint64
	namespace uint32
	event     surveyMatch
	admitted  bool
}

func (c socketCandidate) same(start uint64, ns uint32) bool {
	return c.startTime == start && c.namespace == ns
}

func (c socketCandidate) admittedDuplicate(start uint64, ns uint32) bool {
	return c.same(start, ns) && c.admitted
}

type surveyPIDRegistry interface {
	AllowPID(app.PID, uint32, *exec.FileInfo, ebpfcommon.PIDType)
	BlockPID(app.PID, uint32)
	CurrentPIDs(ebpfcommon.PIDType) map[uint32]map[app.PID]svc.Attrs
}

type surveySocketFilter struct {
	sockets   socketProcesses
	pids      surveyPIDRegistry
	processes map[app.PID]socketCandidate
	startTime func(app.PID) (uint64, error)
	namespace func(app.PID) (uint32, error)
}

func processStartTime(pid app.PID) (uint64, error) {
	p, err := procfs.NewProc(int(pid))
	if err != nil {
		return 0, err
	}
	stat, err := p.Stat()
	return stat.Starttime, err
}

func processNamespace(pid app.PID) (uint32, error) {
	info, err := os.Stat(fmt.Sprintf("/proc/%d/ns/pid", pid))
	if err != nil {
		return 0, err
	}
	return uint32(info.Sys().(*syscall.Stat_t).Ino), nil
}

func surveySocketFilterProvider(cfg *obi.Config, events *ebpfcommon.EBPFEventContext, input, output *msg.Queue[[]surveyMatch]) swarm.InstanceFunc {
	// Subscribe while wiring the graph, before the mixed OBI pipeline can start.
	in := input.Subscribe()
	return func(ctx context.Context) (swarm.RunFunc, error) {
		watchCtx, cancel := context.WithCancel(ctx)

		sockets, err := surveywatcher.Start(watchCtx, cfg, events)
		if err != nil {
			cancel()
			return nil, err
		}

		filter := &surveySocketFilter{
			sockets: sockets, processes: map[app.PID]socketCandidate{},
			startTime: processStartTime, namespace: processNamespace,
			// Register even held candidates: OBI supplies their namespace PID aliases
			// without enabling instrumentation or sharing its instrumentation allowlist.
			pids: ebpfcommon.NewPIDsFilter(&cfg.Discovery, slog.With("component", "survey.SocketFilter"), nil),
		}

		return func(ctx context.Context) {
			defer cancel()
			defer output.Close()
			for {
				var batch []surveyMatch
				select {
				case <-ctx.Done():
					return
				case events, ok := <-in:
					if !ok {
						return
					}
					batch = filter.filter(events)
				case <-sockets.Changes():
					batch = filter.promote()
				}
				if len(batch) > 0 {
					output.SendCtx(ctx, batch)
				}
			}
		}, nil
	}
}

func (f *surveySocketFilter) filter(events []surveyMatch) []surveyMatch {
	var out []surveyMatch

	for _, event := range events {
		if !requiresSurveySocket(event.Obj) {
			out = append(out, event)
			continue
		}

		if event.Type == obiDiscover.EventCreated {
			out = append(out, f.track(event)...)
			continue
		}

		pid := event.Obj.Process.Pid
		previous, exists := f.processes[pid]
		f.remove(pid)

		if exists && previous.admitted {
			out = append(out, event)
		}
	}

	return append(out, f.promote()...)
}

func requiresSurveySocket(match obiDiscover.ProcessMatch) bool {
	for _, criterion := range match.Criteria {
		selector, ok := criterion.(*servicesextra.SurveySelector)
		if !ok || !selector.SocketApps {
			// Survey entries are alternatives: one unrestricted match is enough.
			return false
		}
	}
	return len(match.Criteria) > 0
}

func (f *surveySocketFilter) remove(pid app.PID) {
	if previous, exists := f.processes[pid]; exists {
		f.pids.BlockPID(pid, previous.namespace)
		delete(f.processes, pid)
	}
}

// we normally never add any new processes directly the survey matcher,
// only those that we have admitted and are seen again, perhaps a PID recycle.
func (f *surveySocketFilter) track(event surveyMatch) []surveyMatch {
	pid := event.Obj.Process.Pid
	start, err := f.startTime(pid)
	if err != nil {
		slog.Debug("cannot read survey candidate lifetime", "pid", pid, "error", err)
		return nil
	}

	ns, err := f.namespace(pid)
	if err != nil {
		slog.Debug("cannot read survey candidate namespace", "pid", pid, "error", err)
		return nil
	}

	previous, exists := f.processes[pid]
	if exists && previous.admittedDuplicate(start, ns) {
		return nil
	}

	var out []surveyMatch

	// ship out info that we've deleted a recycled pid
	if exists && previous.admitted {
		deleted := previous.event
		deleted.Type = obiDiscover.EventDeleted
		out = append(out, deleted)
	}

	f.remove(pid)
	f.processes[pid] = socketCandidate{startTime: start, namespace: ns, event: event}

	// we reuse here the OBI pid filter, kprobes type is misleading, I just picked one.
	f.pids.AllowPID(pid, ns, exec.New(exec.Init{
		Pid: pid, Ns: ns, StartTime: start, Service: svc.Attrs{ProcPID: pid},
	}), ebpfcommon.PIDTypeKProbes)

	return out
}

func (f *surveySocketFilter) promote() []surveyMatch {
	var out []surveyMatch

	// All processes are deemed as kprobes, we always put them as kprobes, we are
	// just reusing OBI's pid filter instead of creating our own.
	aliases := f.pids.CurrentPIDs(ebpfcommon.PIDTypeKProbes)
	for identity := range f.sockets.Snapshot() {
		service, ok := aliases[identity.Namespace][app.PID(identity.PID)]
		if !ok {
			continue
		}

		pid := service.ProcPID
		candidate, exists := f.processes[pid]

		// We need to check the namespace and startStart time again because the socket map in eBPF
		// might be stale.
		if !exists || candidate.admitted || !candidate.same(identity.StartTime, identity.Namespace) {
			continue
		}

		// The socket and discovery streams are independent. Don't promote a process
		// that died (or a reused PID) while its discovery deletion is still queued.
		start, err := f.startTime(pid)
		if err != nil || start != candidate.startTime {
			f.remove(pid)
			continue
		}

		candidate.admitted = true
		f.processes[pid] = candidate
		out = append(out, candidate.event)
	}
	return out
}

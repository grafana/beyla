package gpumetrics

import (
	"context"
	"sync"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"

	"github.com/grafana/beyla/v3/pkg/export/otel/bexport"
)

// processes tracks the instrumented processes whose GPU usage can be reported.
type processes struct {
	mu    sync.RWMutex
	byPID map[app.PID]trackedProcess
}

type trackedProcess struct {
	startTime uint64
	uid       svc.UID
}

func newProcesses() *processes { return &processes{byPID: map[app.PID]trackedProcess{}} }

func (p *processes) get(pid uint32) (svc.UID, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	tp, ok := p.byPID[app.PID(pid)]
	return tp.uid, ok
}

func (p *processes) process(event exec.ProcessEvent) {
	if event.File == nil {
		return
	}
	pid, startTime := event.File.Pid(), event.File.StartTime()
	p.mu.Lock()
	defer p.mu.Unlock()
	switch event.Type {
	case exec.ProcessEventCreated:
		attrs := event.File.ServiceAttrs()
		if !attrs.ExportModes.CanExportMetrics() || !bexport.Has(attrs.Features, bexport.FeatureGPU) {
			delete(p.byPID, pid)
			return
		}
		p.byPID[pid] = trackedProcess{startTime: startTime, uid: attrs.UID}
	case exec.ProcessEventTerminated:
		// A delayed termination for an older instance must not remove a reused PID.
		if tp, ok := p.byPID[pid]; ok && tp.startTime == startTime {
			delete(p.byPID, pid)
		}
	}
}

func (p *processes) watch(events *msg.Queue[exec.ProcessEvent], subscriber string) swarm.RunFunc {
	in := events.Subscribe(msg.SubscriberName(subscriber))
	return func(ctx context.Context) {
		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-in:
				if !ok {
					return
				}
				p.process(event)
			}
		}
	}
}

// Package hostinfo exports Beyla-owned host identity without modifying spans.
package hostinfo

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"

	"github.com/grafana/beyla/v3/pkg/export/otel/bexport"
)

// state contains only discovered processes that are still selected for metrics.
// Spans refresh activity but cannot recreate a process after its removal.
type state struct {
	sync.Mutex
	processes map[app.PID]processActivity
}

type processActivity struct {
	startTime uint64
	lastSeen  time.Time
}

func newState() *state { return &state{processes: map[app.PID]processActivity{}} }

func (s *state) observe(pid app.PID, now time.Time) {
	s.Lock()
	defer s.Unlock()
	if activity, exists := s.processes[pid]; exists {
		activity.lastSeen = now
		s.processes[pid] = activity
	}
}

func (s *state) process(event exec.ProcessEvent) {
	if event.File == nil {
		return
	}
	s.Lock()
	defer s.Unlock()
	pid, startTime := event.File.Pid(), event.File.StartTime()
	activity, exists := s.processes[pid]
	switch event.Type {
	case exec.ProcessEventCreated:
		// A repeated discovery event updates metadata without clearing activity.
		// A reused PID starts with no activity from its previous process instance.
		if !exists || activity.startTime != startTime {
			s.processes[pid] = processActivity{startTime: startTime}
		}
	case exec.ProcessEventTerminated:
		// A delayed termination for an older instance must not remove a reused PID.
		if exists && activity.startTime == startTime {
			delete(s.processes, pid)
		}
	}
}

// hasActiveProcesses reports whether a non-terminated process has activity within the metric TTL.
func (s *state) hasActiveProcesses(now time.Time, ttl time.Duration) bool {
	s.Lock()
	defer s.Unlock()
	for _, activity := range s.processes {
		if !activity.lastSeen.IsZero() && now.Sub(activity.lastSeen) < ttl {
			return true
		}
	}
	return false
}

// shouldReportHostInfo checks whether this span can refresh the host-info gauge.
func shouldReportHostInfo(span *request.Span) bool {
	return !span.InternalSignal() && span.Service.ExportModes.CanExportMetrics() &&
		!request.IgnoreMetrics(span) && bexport.Has(span.Service.Features, bexport.FeatureHostInfo)
}

// watchActivity subscribes independently for each exporter without changing the input spans.
func (s *state) watchActivity(input *msg.Queue[[]request.Span], events *msg.Queue[exec.ProcessEvent], subscriber string) swarm.RunFunc {
	spans := input.Subscribe(msg.SubscriberName(subscriber + ".Spans"))
	processes := events.Subscribe(msg.SubscriberName(subscriber + ".Processes"))
	return func(ctx context.Context) {
		for spans != nil || processes != nil {
			select {
			case <-ctx.Done():
				return
			case batch, ok := <-spans:
				if !ok {
					spans = nil
					continue
				}
				now := time.Now()
				for i := range batch {
					if shouldReportHostInfo(&batch[i]) {
						// Match discovery events even when Beyla runs in a PID namespace.
						s.observe(batch[i].Service.ProcPID, now)
					}
				}
			case event, ok := <-processes:
				if !ok {
					processes = nil
					continue
				}
				s.process(event)
			}
		}
	}
}

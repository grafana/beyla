// Package hostinfo exports Beyla-owned host identity without modifying spans.
package hostinfo

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"

	"github.com/grafana/beyla/v3/pkg/export/otel/bexport"
)

// state tracks process activity for one exporter and its asynchronous collector.
type state struct {
	sync.Mutex
	active     map[uint32]time.Time
	terminated map[uint32]bool
}

func newState() *state { return &state{active: map[uint32]time.Time{}, terminated: map[uint32]bool{}} }

func (s *state) observe(pid uint32, now time.Time) {
	s.Lock()
	defer s.Unlock()
	if !s.terminated[pid] {
		s.active[pid] = now
	}
}

func (s *state) process(pid uint32, created bool) {
	s.Lock()
	defer s.Unlock()
	if created {
		delete(s.terminated, pid)
	} else {
		delete(s.active, pid)
		s.terminated[pid] = true
	}
}

// hasActiveProcesses reports whether a non-terminated process has activity within the metric TTL.
func (s *state) hasActiveProcesses(now time.Time, ttl time.Duration) bool {
	s.Lock()
	defer s.Unlock()
	for _, seen := range s.active {
		if now.Sub(seen) < ttl {
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
						s.observe(uint32(batch[i].Pid.HostPID), now)
					}
				}
			case event, ok := <-processes:
				if !ok {
					processes = nil
					continue
				}
				if event.File != nil {
					s.process(uint32(event.File.Pid()), event.Type == exec.ProcessEventCreated)
				}
			}
		}
	}
}

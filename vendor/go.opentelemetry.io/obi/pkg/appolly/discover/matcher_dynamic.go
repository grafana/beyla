// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

type DynamicMatcher struct {
	Log                *slog.Logger
	DynamicPIDSelector services.Selector
	Input              <-chan []Event[ProcessAttrs]
	Output             *msg.Queue[[]Event[ProcessMatch]]
	ProcessHistory     map[app.PID]ProcessMatch
	// RemovedPIDsNotify, when set, carries the PIDs removed from the dynamic selector so the
	// matcher can emit targeted synthetic deletes without rescanning ProcessHistory.
	RemovedPIDsNotify <-chan []app.PID
}

func dynamicMatcherProvider(
	input *msg.Queue[[]Event[ProcessAttrs]],
	output *msg.Queue[[]Event[ProcessMatch]],
	dynamicPIDs *DynamicPIDSelector,
) swarm.InstanceFunc {
	if dynamicPIDs == nil {
		emptyFunc, _ := swarm.EmptyRunFunc()
		return swarm.DirectInstance(emptyFunc)
	}

	dynamicMatcher := &DynamicMatcher{
		Log:                slog.With("component", "discover.DynamicMatcher"),
		DynamicPIDSelector: dynamicPIDs.AsSelector(),
		Input:              input.Subscribe(msg.SubscriberName("discover.DynamicMatcher")),
		Output:             output,
		ProcessHistory:     map[app.PID]ProcessMatch{},
		RemovedPIDsNotify:  dynamicPIDs.RemovedNotify(),
	}
	return swarm.DirectInstance(dynamicMatcher.Run)
}

func (m *DynamicMatcher) Run(ctx context.Context) {
	defer m.Output.Close()
	m.Log.Debug("starting dynamic matcher node")

	for {
		select {
		case <-ctx.Done():
			m.Log.Debug("context done, stopping node")
			return
		case i, ok := <-m.Input:
			if !ok {
				m.Log.Debug("input channel closed, stopping node")
				return
			}
			m.Log.Debug("filtering processes", "len", len(i))
			o := m.filter(i)
			m.Log.Debug("processes matching selection criteria", "len", len(o))
			if len(o) > 0 {
				m.Output.SendCtx(ctx, o)
			}
		case removedPIDs := <-m.RemovedPIDsNotify:
			o := m.syntheticDeletesForRemovedPIDs(removedPIDs)
			if len(o) > 0 {
				m.Log.Debug("synthetic deletes for removed PIDs", "len", len(o))
				m.Output.SendCtx(ctx, o)
			}
		}
	}
}

func (m *DynamicMatcher) filter(events []Event[ProcessAttrs]) []Event[ProcessMatch] {
	var matches []Event[ProcessMatch]
	for _, ev := range events {
		if ev.Type == EventDeleted {
			if ev, ok := m.filterDeleted(ev.Obj); ok {
				matches = append(matches, ev)
			}
		} else {
			if ev, ok := m.filterCreated(ev.Obj); ok {
				matches = append(matches, ev)
			}
		}
	}
	return matches
}

func (m *DynamicMatcher) filterCreated(obj ProcessAttrs) (Event[ProcessMatch], bool) {
	if _, ok := m.ProcessHistory[obj.pid]; ok {
		return Event[ProcessMatch]{}, false
	}

	proc, err := processInfo(obj)
	if err != nil {
		m.Log.Debug("can't get information for process", "pid", obj.pid, "error", err)
		return Event[ProcessMatch]{}, false
	}

	if processMatch := m.matchDynamicCriteria(obj, proc); processMatch != nil {
		m.ProcessHistory[obj.pid] = *processMatch

		return Event[ProcessMatch]{
			Type: EventCreated,
			Obj:  *processMatch,
		}, true
	}

	// We didn't match the process, but let's see if the parent PID is tracked, it might be the child hasn't opened the port yet
	if procMatch, ok := m.ProcessHistory[proc.PPid]; ok {
		m.Log.Debug("found process by matching the process parent id", "pid", proc.Pid, "ppid", proc.PPid, "comm", proc.ExePath, "metadata", obj.metadata)

		procMatch.Process = proc

		m.ProcessHistory[obj.pid] = procMatch

		return Event[ProcessMatch]{
			Type: EventCreated,
			Obj:  procMatch,
		}, true
	}

	return Event[ProcessMatch]{}, false
}

func (m *DynamicMatcher) matchDynamicCriteria(obj ProcessAttrs, proc *services.ProcessInfo) *ProcessMatch {
	criteria := make([]services.Selector, 0, 1)
	if pids, ok := m.DynamicPIDSelector.GetPIDs(); ok && len(pids) > 0 {
		for _, p := range pids {
			if p == proc.Pid {
				criteria = append(criteria, m.DynamicPIDSelector)
				break
			}
		}
	}

	if len(criteria) > 0 {
		m.Log.Debug("found process", "pid", proc.Pid, "comm", proc.ExePath, "metadata",
			obj.metadata, "podLabels", obj.podLabels, "criteria", criteria)

		return &ProcessMatch{Criteria: criteria, Process: proc}
	}

	return nil
}

func (m *DynamicMatcher) filterDeleted(obj ProcessAttrs) (Event[ProcessMatch], bool) {
	procMatch, ok := m.ProcessHistory[obj.pid]
	if !ok {
		m.Log.Debug("deleted untracked process. Ignoring", "pid", obj.pid)
		return Event[ProcessMatch]{}, false
	}
	delete(m.ProcessHistory, obj.pid)
	m.Log.Debug("stopped process", "pid", procMatch.Process.Pid, "comm", procMatch.Process.ExePath)
	return Event[ProcessMatch]{Type: EventDeleted, Obj: procMatch}, true
}

// syntheticDeletesForRemovedPIDs returns EventDeleted for the specific PIDs removed from the
// dynamic selector. This is the matcher side of the edge-based removal path: the selector sends
// the exact removed PIDs, so we can look them up directly instead of doing a level-based scan of
// ProcessHistory against the selector's current PID set.
func (m *DynamicMatcher) syntheticDeletesForRemovedPIDs(removedPIDs []app.PID) []Event[ProcessMatch] {
	if len(removedPIDs) == 0 {
		return nil
	}
	var out []Event[ProcessMatch]
	for _, pid := range removedPIDs {
		procMatch, instrumented := m.ProcessHistory[pid]
		if !instrumented {
			continue
		}
		delete(m.ProcessHistory, pid)
		m.Log.Debug("pid removed from dynamic selector, uninstrumenting", "pid", pid, "comm", procMatch.Process.ExePath)
		out = append(out, Event[ProcessMatch]{Type: EventDeleted, Obj: procMatch})
	}
	return out
}

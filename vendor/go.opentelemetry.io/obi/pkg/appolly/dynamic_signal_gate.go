// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package appolly // import "go.opentelemetry.io/obi/pkg/appolly"

import (
	"context"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
	"go.opentelemetry.io/obi/pkg/selection"
)

func dynamicSignalPID(service *request.Span) app.PID {
	if service.Service.DynamicSelectorPID != 0 {
		return service.Service.DynamicSelectorPID
	}
	return service.Service.ProcPID
}

func processEventSignalPID(file *exec.FileInfo) app.PID {
	snap := file.ServiceAttrs()
	if snap.DynamicSelectorPID != 0 {
		return snap.DynamicSelectorPID
	}
	return file.Pid()
}

func runtimeMetricSignalPID(snapshot runtimemetrics.RuntimeMetricSnapshot) app.PID {
	if snapshot.Service.DynamicSelectorPID != 0 {
		return snapshot.Service.DynamicSelectorPID
	}
	return snapshot.PID
}

// DynamicSignalSpanGate marks spans as traces/metrics-ignored according to the runtime signal views.
func DynamicSignalSpanGate(
	selector selection.MultiSignalPIDSelector,
	input, output *msg.Queue[[]request.Span],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if selector == nil {
			return swarm.Bypass(input, output)
		}
		in := input.Subscribe(msg.SubscriberName("appolly.DynamicSignalSpanGate"))
		tracesSelector := selector.Traces()
		metricsSelector := selector.AppMetrics()
		return func(ctx context.Context) {
			defer output.Close()
			swarms.ForEachInput(ctx, in, nil, func(spans []request.Span) {
				for i := range spans {
					pid := dynamicSignalPID(&spans[i])
					if !tracesSelector.IncludesPID(pid) {
						request.SetIgnoreTraces(&spans[i])
					}
					if !metricsSelector.IncludesPID(pid) {
						request.SetIgnoreMetrics(&spans[i])
					}
				}
				output.SendCtx(ctx, spans)
			})
		}, nil
	}
}

// DynamicSignalRuntimeMetricsGate forwards runtime metric snapshots only for PIDs selected
// for app metrics.
func DynamicSignalRuntimeMetricsGate(
	selector selection.MultiSignalPIDSelector,
	input, output *msg.Queue[[]runtimemetrics.RuntimeMetricSnapshot],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if selector == nil {
			return swarm.Bypass(input, output)
		}
		in := input.Subscribe(msg.SubscriberName("appolly.DynamicSignalRuntimeMetricsGate"))
		metricsSelector := selector.AppMetrics()
		return func(ctx context.Context) {
			defer output.Close()
			swarms.ForEachInput(ctx, in, nil, func(snapshots []runtimemetrics.RuntimeMetricSnapshot) {
				out := filterRuntimeMetricSnapshots(snapshots, metricsSelector)
				if len(out) > 0 {
					output.SendCtx(ctx, out)
				}
			})
		}, nil
	}
}

func filterRuntimeMetricSnapshots(
	snapshots []runtimemetrics.RuntimeMetricSnapshot,
	selector selection.PIDSelector,
) []runtimemetrics.RuntimeMetricSnapshot {
	writeIdx := 0
	for readIdx := range snapshots {
		if selector.IncludesPID(runtimeMetricSignalPID(snapshots[readIdx])) {
			snapshots[writeIdx] = snapshots[readIdx]
			writeIdx++
		}
	}
	return snapshots[:writeIdx]
}

type dynamicSignalProcessEventGate struct {
	input    <-chan exec.ProcessEvent
	output   *msg.Queue[exec.ProcessEvent]
	selector selection.PIDSelector

	current   map[app.PID]*exec.FileInfo
	forwarded map[app.PID]bool
}

// DynamicSignalProcessEventGate forwards process events only for PIDs selected for app metrics.
// It also synthesizes create/delete events when app-metrics selection changes for a process that
// stays instrumented due to traces still being enabled.
func DynamicSignalProcessEventGate(
	selector selection.MultiSignalPIDSelector,
	input, output *msg.Queue[exec.ProcessEvent],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if selector == nil {
			return swarm.Bypass(input, output)
		}
		gate := &dynamicSignalProcessEventGate{
			input:     input.Subscribe(msg.SubscriberName("appolly.DynamicSignalProcessEventGate")),
			output:    output,
			selector:  selector.AppMetrics(),
			current:   map[app.PID]*exec.FileInfo{},
			forwarded: map[app.PID]bool{},
		}
		return gate.run, nil
	}
}

func (g *dynamicSignalProcessEventGate) run(ctx context.Context) {
	defer g.output.Close()

	addedPIDsNotify := selection.AddedPIDsNotifyContext(ctx, g.selector)
	removedPIDsNotify := selection.RemovedNotifyContext(ctx, g.selector)

	for {
		select {
		case <-ctx.Done():
			return
		case pe, ok := <-g.input:
			if !ok {
				return
			}
			g.handleProcessEvent(pe)
		case added, ok := <-addedPIDsNotify:
			if !ok {
				return
			}
			g.handleSelectorAdd(added)
		case removed, ok := <-removedPIDsNotify:
			if !ok {
				return
			}
			g.handleSelectorRemove(removed)
		}
	}
}

func (g *dynamicSignalProcessEventGate) handleProcessEvent(pe exec.ProcessEvent) {
	pid := pe.File.Pid()
	switch pe.Type {
	case exec.ProcessEventCreated:
		g.current[pid] = pe.File
		if g.forwarded[pid] {
			return
		}
		if g.selector.IncludesPID(processEventSignalPID(pe.File)) {
			g.forwarded[pid] = true
			g.output.Send(pe)
		}
	case exec.ProcessEventTerminated:
		if g.forwarded[pid] {
			g.output.Send(pe)
		}
		delete(g.current, pid)
		delete(g.forwarded, pid)
	}
}

func (g *dynamicSignalProcessEventGate) handleSelectorAdd(added []app.PID) {
	if len(added) == 0 {
		return
	}
	for _, signalPID := range added {
		for pid, file := range g.current {
			if g.forwarded[pid] || processEventSignalPID(file) != signalPID {
				continue
			}
			g.forwarded[pid] = true
			g.output.Send(exec.ProcessEvent{Type: exec.ProcessEventCreated, File: file})
		}
	}
}

func (g *dynamicSignalProcessEventGate) handleSelectorRemove(removed []app.PID) {
	if len(removed) == 0 {
		return
	}
	for _, signalPID := range removed {
		for pid, file := range g.current {
			if !g.forwarded[pid] || processEventSignalPID(file) != signalPID {
				continue
			}
			g.forwarded[pid] = false
			g.output.Send(exec.ProcessEvent{Type: exec.ProcessEventTerminated, File: file})
		}
	}
}

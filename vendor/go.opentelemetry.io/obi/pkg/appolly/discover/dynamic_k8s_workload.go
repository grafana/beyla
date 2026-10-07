// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"context"
	"slices"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/selection"
)

// AddK8sWorkload selects a Kubernetes workload for all supported signals. Matching processes
// are materialized into the PID set when discovered. obj may be a typed Kubernetes object
// pointer (e.g. *appsv1.Deployment) or selection.K8sWorkloadRef.
//
// Supported kinds are top-level controllers only: Deployment, StatefulSet, DaemonSet, and
// CronJob (see ParseK8sWorkload).
func (d *DynamicSelector) AddK8sWorkload(obj any, opts selection.DynamicOptions) error {
	return d.rootView.AddK8sWorkload(obj, opts)
}

// RemoveK8sWorkload drops a previously selected Kubernetes workload from all signals and
// dematerializes PIDs that were selected only because of that workload.
func (d *DynamicSelector) RemoveK8sWorkload(obj any) error {
	return d.rootView.RemoveK8sWorkload(obj)
}

// GetK8sWorkloads returns workloads selected for any supported signal.
func (d *DynamicSelector) GetK8sWorkloads() []selection.K8sWorkloadRef {
	return d.rootView.GetK8sWorkloads()
}

// WorkloadsChangedNotifyContext reports when the selected workload set changes for any
// supported signal. Callers that need the current set should call GetK8sWorkloads.
func (d *DynamicSelector) WorkloadsChangedNotifyContext(ctx context.Context) <-chan struct{} {
	return d.workloadsChangedNotifier.SubscribeContext(ctx)
}

// TargetsChangedNotifyContext reports when workload selection changes such that the process
// watcher should rescan already-tracked processes.
func (d *DynamicSelector) TargetsChangedNotifyContext(ctx context.Context) <-chan struct{} {
	return d.targetsChangedNotifier.SubscribeContext(ctx)
}

// AddK8sWorkload selects a Kubernetes workload for this signal view.
func (v *dynamicPIDSignalView) AddK8sWorkload(obj any, opts selection.DynamicOptions) error {
	ref, err := ParseK8sWorkload(obj)
	if err != nil {
		return err
	}
	v.parent.addWorkload(v.mask, workloadKeyFromRef(ref), &opts)
	return nil
}

// RemoveK8sWorkload removes a Kubernetes workload from this signal view.
func (v *dynamicPIDSignalView) RemoveK8sWorkload(obj any) error {
	ref, err := ParseK8sWorkload(obj)
	if err != nil {
		return err
	}
	v.parent.removeWorkload(v.mask, workloadKeyFromRef(ref))
	return nil
}

// GetK8sWorkloads returns workloads selected for this signal view.
func (v *dynamicPIDSignalView) GetK8sWorkloads() []selection.K8sWorkloadRef {
	return v.parent.getWorkloads(v.mask)
}

// WorkloadsChangedNotifyContext reports when the selected workload set changes.
func (v *dynamicPIDSignalView) WorkloadsChangedNotifyContext(ctx context.Context) <-chan struct{} {
	return v.parent.workloadsChangedNotifier.SubscribeContext(ctx)
}

var (
	_ selection.K8sWorkloadSelector = (*DynamicSelector)(nil)
	_ selection.K8sWorkloadSelector = (*dynamicPIDSignalView)(nil)
)

func (d *DynamicSelector) addWorkload(mask dynamicPIDSignal, key workloadKey, opts *selection.DynamicOptions) {
	if mask == 0 {
		return
	}

	var attrsUpdated []app.PID
	var newAttrs dynamicPIDAttributes
	attrsChanged := false

	d.mu.Lock()
	rec := d.byWorkload[key]
	oldMask := rec.signals
	if opts != nil {
		newAttrs = attrsFromOptions(*opts)
		if !attrsEqual(rec.attrs, newAttrs) {
			rec.attrs = newAttrs
			attrsChanged = true
		}
	}
	newMask := oldMask | mask
	rec.signals = newMask
	d.byWorkload[key] = rec
	newlyAdded := oldMask == 0 && newMask != 0
	enteredView := oldMask&mask == 0 && newMask&mask != 0

	if attrsChanged {
		for pid, pidRec := range d.byPID {
			if _, has := pidRec.fromWorkloads[key]; !has {
				continue
			}
			pidRec.attrs = newAttrs
			d.byPID[pid] = pidRec
			attrsUpdated = append(attrsUpdated, pid)
		}
	}
	d.mu.Unlock()

	if newlyAdded || enteredView {
		d.workloadsChangedNotifier.Notify()
		// Nudge the process watcher to re-emit already-tracked processes for metadata rematch.
		d.targetsChangedNotifier.Notify()
	}
	for _, pid := range attrsUpdated {
		d.notifyAttrsUpdated(pid)
	}
}

func (d *DynamicSelector) removeWorkload(mask dynamicPIDSignal, key workloadKey) {
	if mask == 0 {
		return
	}

	removedByView := map[*dynamicPIDSignalView][]app.PID{}
	var workloadRemoved bool
	var oldWorkloadMask, newWorkloadMask dynamicPIDSignal

	d.mu.Lock()
	rec, ok := d.byWorkload[key]
	if !ok {
		d.mu.Unlock()
		return
	}
	oldWorkloadMask = rec.signals
	newWorkloadMask = oldWorkloadMask &^ mask
	if newWorkloadMask == oldWorkloadMask {
		d.mu.Unlock()
		return
	}
	if newWorkloadMask == 0 {
		delete(d.byWorkload, key)
		workloadRemoved = true
	} else {
		rec.signals = newWorkloadMask
		d.byWorkload[key] = rec
	}

	for pid, pidRec := range d.byPID {
		ws, has := pidRec.fromWorkloads[key]
		if !has {
			continue
		}
		oldMask := pidRec.signals
		remaining := ws &^ mask
		if remaining == 0 {
			delete(pidRec.fromWorkloads, key)
		} else {
			pidRec.fromWorkloads[key] = remaining
		}
		newMask := pidRec.recomputedSignals()
		pidRec.signals = newMask
		if newMask == 0 {
			delete(d.byPID, pid)
		} else {
			d.byPID[pid] = pidRec
		}
		if newMask == oldMask {
			continue
		}
		for _, view := range d.views() {
			if view.contains(oldMask) && !view.contains(newMask) {
				removedByView[view] = append(removedByView[view], pid)
			}
		}
	}
	d.mu.Unlock()

	for view, batch := range removedByView {
		view.notifier.notifyRemoved(batch)
	}
	if workloadRemoved || (oldWorkloadMask&mask != 0 && newWorkloadMask&mask == 0) {
		d.workloadsChangedNotifier.Notify()
	}
}

// clearWorkloadSources drops all workload membership for the given PIDs while leaving any
// explicit AddPID/AddPIDs selection intact. Used when a process terminates so materialized
// workload PIDs do not leak; a later matching process rematerializes under the same workload.
func (d *DynamicSelector) clearWorkloadSources(pids ...app.PID) {
	if len(pids) == 0 {
		return
	}
	removedByView := map[*dynamicPIDSignalView][]app.PID{}

	d.mu.Lock()
	for _, pid := range pids {
		rec, ok := d.byPID[pid]
		if !ok || len(rec.fromWorkloads) == 0 {
			continue
		}
		oldMask := rec.signals
		rec.fromWorkloads = nil
		newMask := rec.recomputedSignals()
		rec.signals = newMask
		if newMask == 0 {
			delete(d.byPID, pid)
		} else {
			d.byPID[pid] = rec
		}
		if newMask == oldMask {
			continue
		}
		for _, view := range d.views() {
			if view.contains(oldMask) && !view.contains(newMask) {
				removedByView[view] = append(removedByView[view], pid)
			}
		}
	}
	d.mu.Unlock()

	for view, batch := range removedByView {
		view.notifier.notifyRemoved(batch)
	}
}

func (d *DynamicSelector) getWorkloads(mask dynamicPIDSignal) []selection.K8sWorkloadRef {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.byWorkload) == 0 {
		return nil
	}
	out := make([]selection.K8sWorkloadRef, 0, len(d.byWorkload))
	for key, rec := range d.byWorkload {
		if rec.signals&mask != 0 {
			out = append(out, key.ref())
		}
	}
	slices.SortFunc(out, compareK8sWorkloadRef)
	return out
}

func compareK8sWorkloadRef(a, b selection.K8sWorkloadRef) int {
	if c := strings.Compare(a.Kind, b.Kind); c != 0 {
		return c
	}
	if c := strings.Compare(a.Namespace, b.Namespace); c != 0 {
		return c
	}
	return strings.Compare(a.Name, b.Name)
}

// clearWorkloadSources drops workload membership for pids while keeping explicit AddPID selection.
func (v *dynamicPIDSignalView) clearWorkloadSources(pids ...app.PID) {
	v.parent.clearWorkloadSources(pids...)
}

// materializeMatchingWorkloads finds a selected workload that matches process metadata for
// this view's signal mask and materializes pid into the selector. The full workload signal
// mask is applied (not only this view) so network/stats PID views see the process when the
// workload was selected for them. Callers that need criteria should use SelectorForPID after
// this returns.
func (v *dynamicPIDSignalView) materializeMatchingWorkloads(pid app.PID, meta map[string]string) {
	key, attrs, signals, ok := v.parent.findMatchingWorkload(v.mask, meta)
	if !ok {
		return
	}
	opts := selection.DynamicOptions{
		ServiceName:        attrs.serviceName,
		ServiceNamespace:   attrs.serviceNamespace,
		ResourceAttributes: attrs.resourceAttributes,
	}
	v.parent.addSignalsFrom(signals, &opts, &key, uint32(pid))
}

func (d *DynamicSelector) findMatchingWorkload(
	mask dynamicPIDSignal,
	meta map[string]string,
) (workloadKey, dynamicPIDAttributes, dynamicPIDSignal, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for key, rec := range d.byWorkload {
		if rec.signals&mask == 0 {
			continue
		}
		if workloadMatchesMetadata(key, meta) {
			return key, cloneAttrs(rec.attrs), rec.signals, true
		}
	}
	return workloadKey{}, dynamicPIDAttributes{}, 0, false
}

func attrsEqual(a, b dynamicPIDAttributes) bool {
	if a.serviceName != b.serviceName || a.serviceNamespace != b.serviceNamespace {
		return false
	}
	if len(a.resourceAttributes) != len(b.resourceAttributes) {
		return false
	}
	for k, v := range a.resourceAttributes {
		if b.resourceAttributes[k] != v {
			return false
		}
	}
	return true
}

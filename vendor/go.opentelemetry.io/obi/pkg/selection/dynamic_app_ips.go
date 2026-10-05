// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package selection // import "go.opentelemetry.io/obi/pkg/selection"

import (
	"context"
	"log/slog"
	"sync"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/helpers/container"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
)

func selLog() *slog.Logger {
	return slog.With("component", "selection.DynamicAppIPs")
}

// DynamicAppIPs tracks pod/container IPs for PIDs and Kubernetes workloads in a
// DynamicSelector. It is used by NetO11y and StatsO11y to restrict exported metrics
// to dynamically selected applications.
type DynamicAppIPs struct {
	name     string
	selector PIDSelector
	store    *kube.Store

	mu            sync.RWMutex
	allowedIPs    map[string]int
	pidToIPs      map[app.PID][]string
	workloadToIPs map[K8sWorkloadRef][]string

	// refreshMu serializes full workload IP refreshes so concurrent snapshots cannot
	// commit out of order. wakeRefresh coalesces async refresh requests (including
	// from Store.On, which must not re-enter the store lock).
	refreshMu    sync.Mutex
	wakeRefresh  chan struct{}
	refreshStart sync.Once
}

// NewDynamicAppIPs creates a tracker for the given selector and optional Kubernetes store.
// name must be unique among observers on the same store (e.g. "net", "stats").
func NewDynamicAppIPs(name string, selector PIDSelector, store *kube.Store) *DynamicAppIPs {
	return &DynamicAppIPs{
		name:          name,
		selector:      selector,
		store:         store,
		allowedIPs:    map[string]int{},
		pidToIPs:      map[app.PID][]string{},
		workloadToIPs: map[K8sWorkloadRef][]string{},
		wakeRefresh:   make(chan struct{}, 1),
	}
}

// Run listens for PID add/remove and workload-selection changes and keeps the allowed IP set in sync.
// It also preloads any PIDs and workloads already present in the selector.
func (d *DynamicAppIPs) Run(ctx context.Context) {
	if d.selector == nil {
		return
	}
	d.refreshAll()
	d.refreshWorkloads()
	d.startRefreshLoop(ctx)

	go d.loop(ctx, AddedPIDsNotifyContext(ctx, d.selector), d.addBatch)
	go d.loop(ctx, RemovedNotifyContext(ctx, d.selector), d.removeBatch)

	if ws, ok := d.selector.(K8sWorkloadSelector); ok {
		go d.loopWake(ctx, ws.WorkloadsChangedNotifyContext(ctx), d.requestWorkloadRefresh)
	}

	if d.store != nil {
		d.store.Subscribe(d)
	}
}

func (d *DynamicAppIPs) ID() string {
	return "selection.DynamicAppIPs-" + d.name
}

// On schedules a workload IP refresh when the Kubernetes metadata store changes.
// It must return without calling back into the store: Subscribe invokes observers
// while holding the store lock.
func (d *DynamicAppIPs) On(_ *informer.Event) error {
	d.requestWorkloadRefresh()
	return nil
}

func (d *DynamicAppIPs) startRefreshLoop(ctx context.Context) {
	d.refreshStart.Do(func() {
		go d.refreshLoop(ctx)
	})
}

func (d *DynamicAppIPs) requestWorkloadRefresh() {
	if d.wakeRefresh == nil {
		d.refreshWorkloads()
		return
	}
	select {
	case d.wakeRefresh <- struct{}{}:
	default:
	}
}

func (d *DynamicAppIPs) refreshLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-d.wakeRefresh:
			for {
				select {
				case <-d.wakeRefresh:
					continue
				default:
				}
				break
			}
			d.refreshWorkloads()
		}
	}
}

func (d *DynamicAppIPs) loop(ctx context.Context, ch <-chan []app.PID, fn func([]app.PID)) {
	for {
		select {
		case <-ctx.Done():
			return
		case pids, ok := <-ch:
			if !ok {
				return
			}
			fn(pids)
		}
	}
}

func (d *DynamicAppIPs) loopWake(ctx context.Context, ch <-chan struct{}, fn func()) {
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-ch:
			if !ok {
				return
			}
			fn()
		}
	}
}

func (d *DynamicAppIPs) refreshAll() {
	pids, ok := d.selector.GetPIDs()
	if !ok {
		return
	}
	pidList := make([]app.PID, len(pids))
	copy(pidList, pids)
	d.addBatch(pidList)
}

func (d *DynamicAppIPs) refreshWorkloads() {
	d.refreshMu.Lock()
	defer d.refreshMu.Unlock()

	ws, ok := d.selector.(K8sWorkloadSelector)
	if !ok || d.store == nil {
		d.mu.Lock()
		for _, ips := range d.workloadToIPs {
			d.decrementIPsLocked(ips)
		}
		d.workloadToIPs = map[K8sWorkloadRef][]string{}
		d.mu.Unlock()
		return
	}
	refs := ws.GetK8sWorkloads()
	owners := make([]kube.WorkloadOwner, len(refs))
	for i, ref := range refs {
		owners[i] = kube.WorkloadOwner{Namespace: ref.Namespace, Kind: ref.Kind, Name: ref.Name}
	}
	ipsByOwner := d.store.PodIPsForWorkloads(owners)
	next := map[K8sWorkloadRef][]string{}
	for _, ref := range refs {
		ips := ipsByOwner[kube.WorkloadOwner{Namespace: ref.Namespace, Kind: ref.Kind, Name: ref.Name}]
		if len(ips) == 0 {
			selLog().Debug("no IPs resolved for dynamically selected workload",
				"kind", ref.Kind, "namespace", ref.Namespace, "name", ref.Name)
			continue
		}
		next[ref] = ips
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	for _, ips := range d.workloadToIPs {
		d.decrementIPsLocked(ips)
	}
	d.workloadToIPs = next
	for _, ips := range d.workloadToIPs {
		d.incrementIPsLocked(ips)
	}
}

func (d *DynamicAppIPs) addBatch(pids []app.PID) {
	for _, pid := range pids {
		ips := ResolveContainerIPs(d.store, pid)
		if len(ips) == 0 {
			selLog().Debug("no IPs resolved for dynamically selected PID", "pid", pid)
			continue
		}
		d.mu.Lock()
		if prevIPs, ok := d.pidToIPs[pid]; ok {
			d.decrementIPsLocked(prevIPs)
		}
		d.pidToIPs[pid] = ips
		d.incrementIPsLocked(ips)
		d.mu.Unlock()
	}
}

func (d *DynamicAppIPs) removeBatch(pids []app.PID) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, pid := range pids {
		ips, ok := d.pidToIPs[pid]
		if !ok {
			continue
		}
		delete(d.pidToIPs, pid)
		d.decrementIPsLocked(ips)
		if d.store != nil {
			d.store.DeleteProcess(pid)
		}
	}
}

func (d *DynamicAppIPs) incrementIPsLocked(ips []string) {
	for _, ip := range ips {
		d.allowedIPs[ip]++
	}
}

func (d *DynamicAppIPs) decrementIPsLocked(ips []string) {
	for _, ip := range ips {
		d.allowedIPs[ip]--
		if d.allowedIPs[ip] <= 0 {
			delete(d.allowedIPs, ip)
		}
	}
}

// processIPs lists addresses in pid's netns. Injectable for tests.
var processIPs = func(pid app.PID) []string {
	ips, err := container.IPsForPID(pid)
	if err != nil {
		selLog().Debug("can't list netns IPs for PID", "pid", pid, "error", err)
		return nil
	}
	return ips
}

// ResolveContainerIPs returns the IPs associated with a dynamically selected PID.
//
// The two sources are mutually exclusive. With a Kubernetes store, pod IPs are the only
// source of identity and a PID without pod metadata resolves to nothing. Without a store,
// identity comes from the addresses of an isolated container network namespace
// (Docker/containerd bridge); container.IPsForPID yields nothing for a process sharing
// the host or agent namespace, whose addresses belong to the node rather than to it.
//
// When store is non-nil the PID is registered via AddProcess; callers that invoke
// this outside DynamicAppIPs must call store.DeleteProcess when the PID is no
// longer needed.
func ResolveContainerIPs(store *kube.Store, pid app.PID) []string {
	if store == nil {
		return processIPs(pid)
	}
	store.AddProcess(pid)
	info, err := container.InfoForPID(pid)
	if err != nil {
		selLog().Debug("can't read container info for PID", "pid", pid, "error", err)
		return nil
	}
	meta, _ := store.PodContainerByPIDNs(info.PIDNamespace, pid)
	if meta == nil {
		return nil
	}
	return append([]string(nil), meta.Meta.Ips...)
}

// Allows returns whether a flow/stat record should be exported for the current dynamic selection.
// When the selector is empty, nothing is allowed (exclusive mode, matching DynamicMatcher).
func (d *DynamicAppIPs) Allows(attrs *pipe.CommonAttrs) bool {
	if d.selector == nil {
		return true
	}
	if !d.hasSelection() {
		return false
	}
	src := attrs.SrcAddr.IP().String()
	dst := attrs.DstAddr.IP().String()
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, srcOk := d.allowedIPs[src]
	_, dstOk := d.allowedIPs[dst]
	return srcOk || dstOk
}

func (d *DynamicAppIPs) hasSelection() bool {
	if pids, ok := d.selector.GetPIDs(); ok && len(pids) > 0 {
		return true
	}
	// Workload IPs require kube metadata; without a store they cannot contribute to Allows.
	if d.store != nil {
		if ws, ok := d.selector.(K8sWorkloadSelector); ok && len(ws.GetK8sWorkloads()) > 0 {
			return true
		}
	}
	return false
}

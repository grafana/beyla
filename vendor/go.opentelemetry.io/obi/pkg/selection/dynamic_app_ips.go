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
)

func selLog() *slog.Logger {
	return slog.With("component", "selection.DynamicAppIPs")
}

// DynamicAppIPs tracks pod/container IPs for PIDs in a DynamicPIDSelector. It is used by
// NetO11y and StatsO11y to restrict exported metrics to dynamically selected applications.
type DynamicAppIPs struct {
	selector PIDSelector
	store    *kube.Store

	mu         sync.RWMutex
	allowedIPs map[string]int
	pidToIPs   map[app.PID][]string
}

// NewDynamicAppIPs creates a tracker for the given selector and optional Kubernetes store.
func NewDynamicAppIPs(selector PIDSelector, store *kube.Store) *DynamicAppIPs {
	return &DynamicAppIPs{
		selector:   selector,
		store:      store,
		allowedIPs: map[string]int{},
		pidToIPs:   map[app.PID][]string{},
	}
}

// Run listens for PID add/remove notifications and keeps the allowed IP set in sync.
// It also preloads any PIDs already present in the selector.
func (d *DynamicAppIPs) Run(ctx context.Context) {
	if d.selector == nil {
		return
	}
	d.refreshAll()

	go d.loop(ctx, d.selector.AddedPIDsNotify(), d.addBatch)
	go d.loop(ctx, d.selector.RemovedNotify(), d.removeBatch)
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

func (d *DynamicAppIPs) refreshAll() {
	pids, ok := d.selector.GetPIDs()
	if !ok {
		return
	}
	pidList := make([]app.PID, len(pids))
	copy(pidList, pids)
	d.addBatch(pidList)
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

// ResolveContainerIPs returns pod IPs for a PID when a Kubernetes store is available.
func ResolveContainerIPs(store *kube.Store, pid app.PID) []string {
	if store == nil {
		return nil
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
	if pids, ok := d.selector.GetPIDs(); !ok || len(pids) == 0 {
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

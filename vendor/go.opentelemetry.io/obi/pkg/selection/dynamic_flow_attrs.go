// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package selection // import "go.opentelemetry.io/obi/pkg/selection"

import (
	"context"
	"sync"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/kube"
)

type flowIPDecoration struct {
	serviceName      string
	serviceNamespace string
}

// DynamicFlowAttrs maps dynamically selected application IPs to service identity for NetO11y
// and StatsO11y decoration.
type DynamicFlowAttrs struct {
	multiSel  MultiSignalPIDSelector
	signalSel PIDSelector
	store     *kube.Store

	mu             sync.RWMutex
	ipDecor        map[string]flowIPDecoration
	registeredPIDs map[app.PID]struct{}
}

// NewDynamicFlowAttrs creates a tracker for the given signal view and optional Kubernetes store.
func NewDynamicFlowAttrs(multiSel MultiSignalPIDSelector, signalSel PIDSelector, store *kube.Store) *DynamicFlowAttrs {
	return &DynamicFlowAttrs{
		multiSel:       multiSel,
		signalSel:      signalSel,
		store:          store,
		ipDecor:        map[string]flowIPDecoration{},
		registeredPIDs: map[app.PID]struct{}{},
	}
}

// Run keeps the IP decoration map in sync with PID membership and attribute updates.
func (d *DynamicFlowAttrs) Run(ctx context.Context) {
	if d.multiSel == nil || d.signalSel == nil {
		return
	}
	d.rebuild()

	go d.loop(ctx, AddedPIDsNotifyContext(ctx, d.signalSel), d.rebuild)
	go d.loop(ctx, RemovedNotifyContext(ctx, d.signalSel), d.rebuild)
	go d.loopAttrs(ctx)
}

func (d *DynamicFlowAttrs) loop(ctx context.Context, ch <-chan []app.PID, fn func()) {
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

func (d *DynamicFlowAttrs) loopAttrs(ctx context.Context) {
	ch := d.multiSel.AttrsUpdatedNotify()
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-ch:
			if !ok {
				return
			}
			d.rebuild()
		}
	}
}

func (d *DynamicFlowAttrs) rebuild() {
	pids, ok := d.signalSel.GetPIDs()

	next := map[string]flowIPDecoration{}
	storeRegisteredPIDs := map[app.PID]struct{}{}
	if ok && d.store != nil {
		for _, pid := range pids {
			entry, found := d.multiSel.GetPID(uint32(pid))
			if !found {
				continue
			}
			dec := decorationFromEntry(entry)
			if dec.isEmpty() {
				continue
			}
			for _, ip := range ResolveContainerIPs(d.store, pid) {
				next[ip] = dec
			}
			storeRegisteredPIDs[pid] = struct{}{}
		}
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	for pid := range d.registeredPIDs {
		if _, still := storeRegisteredPIDs[pid]; !still {
			if d.store != nil {
				d.store.DeleteProcess(pid)
			}
			delete(d.registeredPIDs, pid)
		}
	}
	for pid := range storeRegisteredPIDs {
		d.registeredPIDs[pid] = struct{}{}
	}
	d.ipDecor = next
}

func (d *DynamicFlowAttrs) Apply(a *pipe.CommonAttrs) {
	if a == nil {
		return
	}
	d.mu.RLock()
	srcDec, srcOk := d.ipDecor[a.SrcAddr.IP().String()]
	dstDec, dstOk := d.ipDecor[a.DstAddr.IP().String()]
	d.mu.RUnlock()
	if !srcOk && !dstOk {
		return
	}
	if a.Metadata == nil {
		a.Metadata = map[attr.Name]string{}
	}
	if srcOk {
		applyFlowDecoration(srcDec, a, true)
	}
	if dstOk {
		applyFlowDecoration(dstDec, a, false)
	}
}

func decorationFromEntry(entry DynamicPIDEntry) flowIPDecoration {
	return flowIPDecoration{
		serviceName:      entry.ServiceName,
		serviceNamespace: entry.ServiceNamespace,
	}
}

func (d flowIPDecoration) isEmpty() bool {
	return d.serviceName == "" && d.serviceNamespace == ""
}

func applyFlowDecoration(dec flowIPDecoration, a *pipe.CommonAttrs, src bool) {
	if src {
		if dec.serviceName != "" {
			a.Metadata[attr.ServiceName] = dec.serviceName
		}
		if dec.serviceNamespace != "" {
			a.Metadata[attr.ServiceNamespace] = dec.serviceNamespace
		}
		return
	}
	if dec.serviceName != "" {
		a.Metadata[attr.ServicePeerName] = dec.serviceName
	}
	if dec.serviceNamespace != "" {
		a.Metadata[attr.ServicePeerNamespace] = dec.serviceNamespace
	}
}

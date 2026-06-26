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
	resourceAttrs    map[attr.Name]string
}

// DynamicFlowAttrs maps dynamically selected application IPs to service identity and resource
// attributes for NetO11y and StatsO11y decoration.
type DynamicFlowAttrs struct {
	multiSel  MultiSignalPIDSelector
	signalSel PIDSelector
	store     *kube.Store

	mu      sync.RWMutex
	ipDecor map[string]flowIPDecoration
}

// NewDynamicFlowAttrs creates a tracker for the given signal view and optional Kubernetes store.
func NewDynamicFlowAttrs(multiSel MultiSignalPIDSelector, signalSel PIDSelector, store *kube.Store) *DynamicFlowAttrs {
	return &DynamicFlowAttrs{
		multiSel:  multiSel,
		signalSel: signalSel,
		store:     store,
		ipDecor:   map[string]flowIPDecoration{},
	}
}

// Run keeps the IP decoration map in sync with PID membership and attribute updates.
func (d *DynamicFlowAttrs) Run(ctx context.Context) {
	if d.multiSel == nil || d.signalSel == nil {
		return
	}
	d.rebuild()

	go d.loop(ctx, d.signalSel.AddedPIDsNotify(), d.rebuild)
	go d.loop(ctx, d.signalSel.RemovedNotify(), d.rebuild)
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
	if !ok {
		d.mu.Lock()
		d.ipDecor = map[string]flowIPDecoration{}
		d.mu.Unlock()
		return
	}

	next := map[string]flowIPDecoration{}
	for _, pid := range pids {
		entry, ok := d.multiSel.GetPID(uint32(pid))
		if !ok {
			continue
		}
		dec := decorationFromEntry(entry)
		if dec.isEmpty() {
			continue
		}
		for _, ip := range ResolveContainerIPs(d.store, pid) {
			next[ip] = dec
		}
	}

	d.mu.Lock()
	d.ipDecor = next
	d.mu.Unlock()
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
	dec := flowIPDecoration{
		serviceName:      entry.ServiceName,
		serviceNamespace: entry.ServiceNamespace,
	}
	if len(entry.ResourceAttributes) > 0 {
		dec.resourceAttrs = make(map[attr.Name]string, len(entry.ResourceAttributes))
		for k, v := range entry.ResourceAttributes {
			dec.resourceAttrs[attr.Name(k)] = v
		}
	}
	return dec
}

func (d flowIPDecoration) isEmpty() bool {
	return d.serviceName == "" && d.serviceNamespace == "" && len(d.resourceAttrs) == 0
}

func applyFlowDecoration(dec flowIPDecoration, a *pipe.CommonAttrs, src bool) {
	if src {
		if dec.serviceName != "" {
			a.Metadata[attr.ServiceName] = dec.serviceName
		}
		if dec.serviceNamespace != "" {
			a.Metadata[attr.ServiceNamespace] = dec.serviceNamespace
		}
	} else {
		if dec.serviceName != "" {
			a.Metadata[attr.ServicePeerName] = dec.serviceName
		}
		if dec.serviceNamespace != "" {
			a.Metadata[attr.ServicePeerNamespace] = dec.serviceNamespace
		}
	}
	for k, v := range dec.resourceAttrs {
		a.Metadata[k] = v
	}
}

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"iter"
	"sync"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
)

// DynamicPIDSelector holds the runtime set of target PIDs for OBI. It is preloaded from
// config target_pids and updated at runtime via AddPIDs/RemovePIDs. Only the discover
// matcher uses it for matching; the instrumenter (or appolly) holds a reference and
// calls AddPIDs/RemovePIDs directly.
//
// Pending add/remove PIDs are accumulated in slices and drained by goroutines into
// RemovedNotify() and AddedPIDsNotify(), so callers never block and nothing is dropped.
type DynamicPIDSelector struct {
	mu   sync.RWMutex
	pids []uint32

	removedCh      chan []app.PID // consumer receives from this
	removedPending []app.PID      // PIDs to send on next drain
	removedMu      sync.Mutex
	removedCond    *sync.Cond

	addedCh      chan []app.PID // consumer receives from this
	addedPending []app.PID      // PIDs to send on next drain
	addedMu      sync.Mutex
	addedCond    *sync.Cond
}

// NewDynamicPIDSelector creates a new dynamic PID selector (initially empty).
// It starts goroutines that drain pending add/remove PIDs to the notify channels.
func NewDynamicPIDSelector() *DynamicPIDSelector {
	d := &DynamicPIDSelector{
		removedCh: make(chan []app.PID, 1),
		addedCh:   make(chan []app.PID, 1),
	}
	d.removedCond = sync.NewCond(&d.removedMu)
	d.addedCond = sync.NewCond(&d.addedMu)
	go d.drainRemoved()
	go d.drainAdded()
	return d
}

// RemovedNotify returns the channel on which removed PIDs are sent when RemovePIDs is called.
// The matcher uses this to emit synthetic deletes. Safe to call from multiple goroutines.
func (d *DynamicPIDSelector) RemovedNotify() <-chan []app.PID {
	return d.removedCh
}

// AddedPIDsNotify returns the channel on which newly added PIDs are sent when AddPIDs is called.
// The process watcher uses this to forget those PIDs from its tracked state so they are re-emitted
// as new on the next poll (supporting adding an already-seen process to the dynamic set).
func (d *DynamicPIDSelector) AddedPIDsNotify() <-chan []app.PID {
	return d.addedCh
}

// GetPIDs returns a copy of the current PID list and true when non-empty.
func (d *DynamicPIDSelector) GetPIDs() ([]app.PID, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.pids) == 0 {
		return nil, false
	}
	out := make([]app.PID, len(d.pids))
	for i, p := range d.pids {
		out[i] = app.PID(p)
	}
	return out, true
}

// AddPIDs adds PIDs to the set (deduplicated). Newly added PIDs are sent on AddedPIDsNotify()
// so the process watcher can forget them and re-emit them as new on the next poll.
func (d *DynamicPIDSelector) AddPIDs(pids ...uint32) {
	if len(pids) == 0 {
		return
	}
	d.mu.Lock()
	existing := make(map[uint32]struct{}, len(d.pids))
	for _, p := range d.pids {
		existing[p] = struct{}{}
	}
	var added []app.PID
	for _, u := range pids {
		if _, ok := existing[u]; !ok {
			existing[u] = struct{}{}
			d.pids = append(d.pids, u)
			added = append(added, app.PID(u))
		}
	}
	d.mu.Unlock()
	d.notifyAdded(added)
}

// RemovePIDs removes PIDs from the set and sends them on RemovedNotify() for the matcher.
func (d *DynamicPIDSelector) RemovePIDs(pids ...uint32) {
	if len(pids) == 0 {
		return
	}
	toRemove := make(map[uint32]struct{})
	for _, u := range pids {
		toRemove[u] = struct{}{}
	}
	d.mu.Lock()
	newPids := d.pids[:0]
	removedPIDs := make([]app.PID, 0, len(pids))
	for _, p := range d.pids {
		if _, remove := toRemove[p]; !remove {
			newPids = append(newPids, p)
			continue
		}
		removedPIDs = append(removedPIDs, app.PID(p))
	}
	d.pids = newPids
	d.mu.Unlock()
	d.notifyRemoved(removedPIDs)
}

func (d *DynamicPIDSelector) notifyRemoved(removedPIDs []app.PID) {
	if len(removedPIDs) == 0 {
		return
	}
	d.removedMu.Lock()
	d.removedPending = append(d.removedPending, removedPIDs...)
	d.removedCond.Signal()
	d.removedMu.Unlock()
}

func (d *DynamicPIDSelector) notifyAdded(addedPIDs []app.PID) {
	if len(addedPIDs) == 0 {
		return
	}
	d.addedMu.Lock()
	d.addedPending = append(d.addedPending, addedPIDs...)
	d.addedCond.Signal()
	d.addedMu.Unlock()
}

// drainRemoved runs in a goroutine; it sends the current pending removed PIDs and clears the slice.
func (d *DynamicPIDSelector) drainRemoved() {
	for {
		d.removedMu.Lock()
		for len(d.removedPending) == 0 {
			d.removedCond.Wait()
		}
		batch := append([]app.PID(nil), d.removedPending...)
		d.removedPending = d.removedPending[:0]
		d.removedMu.Unlock()
		d.removedCh <- batch
	}
}

// drainAdded runs in a goroutine; it sends the current pending added PIDs and clears the slice.
func (d *DynamicPIDSelector) drainAdded() {
	for {
		d.addedMu.Lock()
		for len(d.addedPending) == 0 {
			d.addedCond.Wait()
		}
		batch := append([]app.PID(nil), d.addedPending...)
		d.addedPending = d.addedPending[:0]
		d.addedMu.Unlock()
		d.addedCh <- batch
	}
}

// AsSelector returns a services.Selector that matches when the process PID is in this dynamic set.
// The matcher uses it to treat runtime PIDs as a supplement to config criteria.
func (d *DynamicPIDSelector) AsSelector() services.Selector {
	return &dynamicPIDCriteriaAdapter{d: d}
}

// dynamicPIDCriteriaAdapter implements services.Selector by delegating only GetPIDs to the
// DynamicPIDSelector; all other methods return empty/zero so the matcher treats "PID in dynamic set"
// as a match.
type dynamicPIDCriteriaAdapter struct {
	d *DynamicPIDSelector
}

func (a *dynamicPIDCriteriaAdapter) GetName() string                       { return "" }
func (a *dynamicPIDCriteriaAdapter) GetNamespace() string                  { return "" }
func (a *dynamicPIDCriteriaAdapter) GetPath() services.StringMatcher       { return &emptyMatcher{} }
func (a *dynamicPIDCriteriaAdapter) GetPathRegexp() services.StringMatcher { return &emptyMatcher{} }
func (a *dynamicPIDCriteriaAdapter) GetOpenPorts() *services.IntEnum       { return &services.IntEnum{} }
func (a *dynamicPIDCriteriaAdapter) GetLanguages() services.StringMatcher  { return &emptyMatcher{} }
func (a *dynamicPIDCriteriaAdapter) GetPIDs() ([]app.PID, bool)            { return a.d.GetPIDs() }
func (a *dynamicPIDCriteriaAdapter) GetCmdArgs() services.StringMatcher    { return &emptyMatcher{} }
func (a *dynamicPIDCriteriaAdapter) IsContainersOnly() bool                { return false }
func (a *dynamicPIDCriteriaAdapter) RangeMetadata() iter.Seq2[string, services.StringMatcher] {
	return emptyMetadataSeq2
}

func (a *dynamicPIDCriteriaAdapter) RangePodLabels() iter.Seq2[string, services.StringMatcher] {
	return emptyMetadataSeq2
}

func (a *dynamicPIDCriteriaAdapter) RangePodAnnotations() iter.Seq2[string, services.StringMatcher] {
	return emptyMetadataSeq2
}

func (a *dynamicPIDCriteriaAdapter) GetExportModes() services.ExportModes {
	return services.ExportModeUnset
}

func (a *dynamicPIDCriteriaAdapter) GetSamplerConfig() *services.SamplerConfig     { return nil }
func (a *dynamicPIDCriteriaAdapter) GetRoutesConfig() *services.CustomRoutesConfig { return nil }
func (a *dynamicPIDCriteriaAdapter) MetricsConfig() perapp.SvcMetricsConfig {
	return perapp.SvcMetricsConfig{}
}

type emptyMatcher struct{}

func (emptyMatcher) IsSet() bool               { return false }
func (emptyMatcher) MatchString(_ string) bool { return false }

func emptyMetadataSeq2(_ func(string, services.StringMatcher) bool) {}

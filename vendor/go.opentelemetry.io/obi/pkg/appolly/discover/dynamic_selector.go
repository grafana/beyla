// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"context"
	"iter"
	"maps"
	"slices"
	"sync"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/selection"
)

type dynamicPIDSignal uint8

const (
	signalTraces dynamicPIDSignal = 1 << iota
	signalAppMetrics
	signalNetworkMetrics
	signalStatsMetrics
)

const (
	appSignalMask dynamicPIDSignal = signalTraces | signalAppMetrics
	allSignalMask dynamicPIDSignal = appSignalMask | signalNetworkMetrics | signalStatsMetrics
)

// TODO: support per-signal attribute overrides; attributes are currently shared across all signals.

type dynamicPIDAttributes struct {
	serviceName        string
	serviceNamespace   string
	resourceAttributes map[string]string
}

type dynamicPIDRecord struct {
	signals         dynamicPIDSignal
	attrs           dynamicPIDAttributes
	explicitSignals dynamicPIDSignal
	fromWorkloads   map[workloadKey]dynamicPIDSignal
}

type dynamicWorkloadRecord struct {
	signals dynamicPIDSignal
	attrs   dynamicPIDAttributes
}

func (r dynamicPIDRecord) recomputedSignals() dynamicPIDSignal {
	mask := r.explicitSignals
	for _, ws := range r.fromWorkloads {
		mask |= ws
	}
	return mask
}

type dynamicPIDSignalView struct {
	parent   *DynamicSelector
	mask     dynamicPIDSignal
	notifier *dynamicEdgePairNotifier[app.PID]
}

func (v *dynamicPIDSignalView) AddPIDs(pids ...uint32) {
	v.parent.addSignals(v.mask, nil, pids...)
}

func (v *dynamicPIDSignalView) AddPID(pid uint32, opts selection.DynamicOptions) {
	v.parent.addSignals(v.mask, &opts, pid)
}

func (v *dynamicPIDSignalView) RemovePIDs(pids ...uint32) {
	v.parent.removeSignals(v.mask, pids...)
}

func (v *dynamicPIDSignalView) GetPIDs() ([]app.PID, bool) {
	return v.parent.getPIDs(v.mask)
}

func (v *dynamicPIDSignalView) IncludesPID(pid app.PID) bool {
	return v.parent.includesPID(v.mask, pid)
}

func (v *dynamicPIDSignalView) AddedPIDsNotify() <-chan []app.PID {
	return v.notifier.addedNotify()
}

func (v *dynamicPIDSignalView) AddedPIDsNotifyContext(ctx context.Context) <-chan []app.PID {
	return v.notifier.addedNotifyContext(ctx)
}

func (v *dynamicPIDSignalView) RemovedNotify() <-chan []app.PID {
	return v.notifier.removedNotify()
}

func (v *dynamicPIDSignalView) RemovedNotifyContext(ctx context.Context) <-chan []app.PID {
	return v.notifier.removedNotifyContext(ctx)
}

// SelectorForPID returns a services.Selector for pid when it is in this view, carrying the
// PID's shared service name and resource attributes.
func (v *dynamicPIDSignalView) SelectorForPID(pid app.PID) services.Selector {
	if !v.IncludesPID(pid) {
		return nil
	}
	return v.parent.selectorForPID(pid)
}

// AsSelector returns a services.Selector that matches when the process PID is in this dynamic view.
func (v *dynamicPIDSignalView) AsSelector() services.Selector {
	return &dynamicPIDCriteriaAdapter{view: v}
}

// DynamicSelector holds one runtime selector object with per-signal PID views. The root Add/Remove
// methods preserve legacy behavior by applying to all supported signals.
//
// Callers may also select Kubernetes workloads via AddK8sWorkload; matching processes are
// materialized into the PID set so existing signal gates and network/stats IP tracking keep working.
type DynamicSelector struct {
	mu         sync.RWMutex
	byPID      map[app.PID]dynamicPIDRecord
	byWorkload map[workloadKey]dynamicWorkloadRecord

	fileInfoMu        sync.RWMutex
	fileInfoByPID     map[app.PID]*exec.FileInfo
	onFileInfoUpdated func(*exec.FileInfo)
	attrsUpdatedCh    chan app.PID

	targetsChangedNotifier   *dynamicWakeNotifier
	workloadsChangedNotifier *dynamicWakeNotifier

	rootView           dynamicPIDSignalView
	tracesView         dynamicPIDSignalView
	appMetricsView     dynamicPIDSignalView
	networkMetricsView dynamicPIDSignalView
	statsMetricsView   dynamicPIDSignalView
	appSignalsView     dynamicPIDSignalView
}

var _ selection.MultiSignalPIDSelector = (*DynamicSelector)(nil)

func newDynamicPIDSignalView(parent *DynamicSelector, mask dynamicPIDSignal) dynamicPIDSignalView {
	return dynamicPIDSignalView{
		parent:   parent,
		mask:     mask,
		notifier: newDynamicEdgePairNotifier[app.PID](),
	}
}

// NewDynamicSelector creates a new selector whose root Add/Remove methods apply to all signals.
func NewDynamicSelector() *DynamicSelector {
	d := &DynamicSelector{
		byPID:                    map[app.PID]dynamicPIDRecord{},
		byWorkload:               map[workloadKey]dynamicWorkloadRecord{},
		fileInfoByPID:            map[app.PID]*exec.FileInfo{},
		attrsUpdatedCh:           make(chan app.PID, 64),
		targetsChangedNotifier:   newDynamicWakeNotifier(),
		workloadsChangedNotifier: newDynamicWakeNotifier(),
	}
	d.rootView = newDynamicPIDSignalView(d, allSignalMask)
	d.tracesView = newDynamicPIDSignalView(d, signalTraces)
	d.appMetricsView = newDynamicPIDSignalView(d, signalAppMetrics)
	d.networkMetricsView = newDynamicPIDSignalView(d, signalNetworkMetrics)
	d.statsMetricsView = newDynamicPIDSignalView(d, signalStatsMetrics)
	d.appSignalsView = newDynamicPIDSignalView(d, appSignalMask)
	return d
}

// SetOnFileInfoUpdated registers a hook invoked after SetPID updates a live FileInfo. OBI uses this
// to re-send process events so metrics exporters refresh target_info and related series.
func (d *DynamicSelector) SetOnFileInfoUpdated(fn func(*exec.FileInfo)) {
	d.fileInfoMu.Lock()
	d.onFileInfoUpdated = fn
	d.fileInfoMu.Unlock()
}

// AttrsUpdatedNotify reports PIDs whose shared attributes changed.
func (d *DynamicSelector) AttrsUpdatedNotify() <-chan app.PID {
	return d.attrsUpdatedCh
}

func (d *DynamicSelector) notifyAttrsUpdated(pid app.PID) {
	select {
	case d.attrsUpdatedCh <- pid:
	default:
	}
}

// RegisterFileInfo records the live FileInfo for a dynamically selected PID after instrumentation.
func (d *DynamicSelector) RegisterFileInfo(pid app.PID, fi *exec.FileInfo) {
	if fi == nil {
		return
	}
	d.fileInfoMu.Lock()
	d.fileInfoByPID[pid] = fi
	if owner := fi.ServiceAttrs().DynamicSelectorPID; owner != 0 && owner != pid {
		d.fileInfoByPID[owner] = fi
	}
	d.fileInfoMu.Unlock()
}

// UnregisterFileInfo drops FileInfo references for pid and its dynamic selector owner PID.
func (d *DynamicSelector) UnregisterFileInfo(pid app.PID, fi *exec.FileInfo) {
	d.fileInfoMu.Lock()
	delete(d.fileInfoByPID, pid)
	if fi != nil {
		if owner := fi.ServiceAttrs().DynamicSelectorPID; owner != 0 {
			delete(d.fileInfoByPID, owner)
		}
	}
	d.fileInfoMu.Unlock()
}

func (d *DynamicSelector) views() []*dynamicPIDSignalView {
	return []*dynamicPIDSignalView{
		&d.rootView,
		&d.tracesView,
		&d.appMetricsView,
		&d.networkMetricsView,
		&d.statsMetricsView,
		&d.appSignalsView,
	}
}

func (d *DynamicSelector) addSignals(mask dynamicPIDSignal, opts *selection.DynamicOptions, pids ...uint32) {
	d.addSignalsFrom(mask, opts, nil, pids...)
}

func (d *DynamicSelector) addSignalsFrom(
	mask dynamicPIDSignal,
	opts *selection.DynamicOptions,
	from *workloadKey,
	pids ...uint32,
) {
	if len(pids) == 0 || mask == 0 {
		return
	}
	addedByView := map[*dynamicPIDSignalView][]app.PID{}
	var attrsUpdated []app.PID

	d.mu.Lock()
	for _, rawPID := range pids {
		pid := app.PID(rawPID)
		rec := d.byPID[pid]
		oldMask := rec.signals

		if opts != nil {
			rec.attrs = attrsFromOptions(*opts)
		}

		if from == nil {
			rec.explicitSignals |= mask
		} else {
			if rec.fromWorkloads == nil {
				rec.fromWorkloads = map[workloadKey]dynamicPIDSignal{}
			}
			rec.fromWorkloads[*from] |= mask
		}
		newMask := rec.recomputedSignals()
		rec.signals = newMask

		if newMask == oldMask {
			if opts != nil {
				d.byPID[pid] = rec
				attrsUpdated = append(attrsUpdated, pid)
			}
			continue
		}
		d.byPID[pid] = rec

		for _, view := range d.views() {
			if !view.contains(oldMask) && view.contains(newMask) {
				addedByView[view] = append(addedByView[view], pid)
			}
		}
	}
	d.mu.Unlock()

	for view, batch := range addedByView {
		view.notifier.notifyAdded(batch)
	}
	for _, pid := range attrsUpdated {
		d.notifyAttrsUpdated(pid)
	}
}

func (d *DynamicSelector) removeSignals(mask dynamicPIDSignal, pids ...uint32) {
	if len(pids) == 0 {
		return
	}
	removedByView := map[*dynamicPIDSignalView][]app.PID{}

	d.mu.Lock()
	for _, rawPID := range pids {
		pid := app.PID(rawPID)
		rec, ok := d.byPID[pid]
		if !ok {
			continue
		}
		oldMask := rec.signals

		// Explicit RemovePIDs clears the requested signals from all sources.
		rec.explicitSignals &^= mask
		for key, ws := range rec.fromWorkloads {
			remaining := ws &^ mask
			if remaining == 0 {
				delete(rec.fromWorkloads, key)
			} else {
				rec.fromWorkloads[key] = remaining
			}
		}
		newMask := rec.recomputedSignals()
		if newMask == oldMask {
			continue
		}
		if newMask == 0 {
			delete(d.byPID, pid)
		} else {
			rec.signals = newMask
			d.byPID[pid] = rec
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

func (d *DynamicSelector) getPIDs(mask dynamicPIDSignal) ([]app.PID, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.byPID) == 0 {
		return nil, false
	}
	out := make([]app.PID, 0, len(d.byPID))
	for pid, rec := range d.byPID {
		if rec.signals&mask != 0 {
			out = append(out, pid)
		}
	}
	if len(out) == 0 {
		return nil, false
	}
	slices.Sort(out)
	return out, true
}

func (d *DynamicSelector) includesPID(mask dynamicPIDSignal, pid app.PID) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.byPID[pid].signals&mask != 0
}

func (d *DynamicSelector) selectorForPID(pid app.PID) services.Selector {
	d.mu.RLock()
	rec, ok := d.byPID[pid]
	d.mu.RUnlock()
	if !ok {
		return nil
	}
	return newDynamicPIDCriteriaAdapter(pid, rec.attrs)
}

// GetPID returns the shared attributes for a tracked PID.
func (d *DynamicSelector) GetPID(pid uint32) (selection.DynamicPIDEntry, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	rec, ok := d.byPID[app.PID(pid)]
	if !ok {
		return selection.DynamicPIDEntry{}, false
	}
	return entryFromRecord(app.PID(pid), rec.attrs), true
}

// SetPID updates shared attributes for a PID that is already tracked by the selector and, when
// the process is instrumented, applies them to its live FileInfo.
func (d *DynamicSelector) SetPID(entry selection.DynamicPIDEntry) bool {
	attrs := attrsFromEntry(entry)

	d.mu.Lock()
	rec, ok := d.byPID[entry.PID]
	if !ok {
		d.mu.Unlock()
		return false
	}
	d.byPID[entry.PID] = dynamicPIDRecord{
		signals:         rec.signals,
		attrs:           attrs,
		explicitSignals: rec.explicitSignals,
		fromWorkloads:   rec.fromWorkloads,
	}
	d.mu.Unlock()

	d.applyAttrsToInstrumented(entry.PID, attrs)
	d.notifyAttrsUpdated(entry.PID)
	return true
}

func (d *DynamicSelector) applyAttrsToInstrumented(pid app.PID, attrs dynamicPIDAttributes) {
	d.fileInfoMu.RLock()
	fi := d.fileInfoByPID[pid]
	cb := d.onFileInfoUpdated
	d.fileInfoMu.RUnlock()
	if fi == nil {
		return
	}
	updated := false
	if attrs.serviceName != "" || attrs.serviceNamespace != "" {
		uid := fi.ServiceAttrs().UID
		if attrs.serviceName != "" {
			uid.Name = attrs.serviceName
		}
		if attrs.serviceNamespace != "" {
			uid.Namespace = attrs.serviceNamespace
		}
		fi.SetUID(uid)
		updated = true
	}
	if len(attrs.resourceAttributes) > 0 {
		snap := fi.ServiceAttrs()
		metadata := snap.Metadata
		if metadata == nil {
			metadata = map[attr.Name]string{}
		} else {
			metadata = maps.Clone(metadata)
		}
		for k, v := range attrs.resourceAttributes {
			metadata[attr.Name(k)] = v
		}
		fi.SetMetadata(metadata)
		updated = true
	}
	if updated && cb != nil {
		cb(fi)
	}
}

func (v *dynamicPIDSignalView) contains(mask dynamicPIDSignal) bool {
	return mask&v.mask != 0
}

// AddPID adds a PID to all supported signals with optional shared attributes.
func (d *DynamicSelector) AddPID(pid uint32, opts selection.DynamicOptions) {
	d.rootView.AddPID(pid, opts)
}

// AddPIDs adds PIDs to all supported signals (legacy root behavior).
func (d *DynamicSelector) AddPIDs(pids ...uint32) {
	d.rootView.AddPIDs(pids...)
}

// RemovePIDs removes PIDs from all supported signals (legacy root behavior).
func (d *DynamicSelector) RemovePIDs(pids ...uint32) {
	d.rootView.RemovePIDs(pids...)
}

// GetPIDs returns PIDs selected for any supported signal.
func (d *DynamicSelector) GetPIDs() ([]app.PID, bool) {
	return d.rootView.GetPIDs()
}

// IncludesPID reports whether pid is selected for any supported signal.
func (d *DynamicSelector) IncludesPID(pid app.PID) bool {
	return d.rootView.IncludesPID(pid)
}

// AddedPIDsNotify returns the channel on which PIDs are sent when they enter the root view.
func (d *DynamicSelector) AddedPIDsNotify() <-chan []app.PID {
	return d.rootView.AddedPIDsNotify()
}

func (d *DynamicSelector) AddedPIDsNotifyContext(ctx context.Context) <-chan []app.PID {
	return d.rootView.AddedPIDsNotifyContext(ctx)
}

// RemovedNotify returns the channel on which PIDs are sent when they leave the root view.
func (d *DynamicSelector) RemovedNotify() <-chan []app.PID {
	return d.rootView.RemovedNotify()
}

func (d *DynamicSelector) RemovedNotifyContext(ctx context.Context) <-chan []app.PID {
	return d.rootView.RemovedNotifyContext(ctx)
}

// Traces returns the mutable selector view for trace signals.
func (d *DynamicSelector) Traces() selection.MutablePIDSelector {
	return &d.tracesView
}

// AppMetrics returns the mutable selector view for application metrics signals.
func (d *DynamicSelector) AppMetrics() selection.MutablePIDSelector {
	return &d.appMetricsView
}

// NetworkMetrics returns the mutable selector view for network metrics signals.
func (d *DynamicSelector) NetworkMetrics() selection.MutablePIDSelector {
	return &d.networkMetricsView
}

// StatsMetrics returns the mutable selector view for stats metrics signals.
func (d *DynamicSelector) StatsMetrics() selection.MutablePIDSelector {
	return &d.statsMetricsView
}

func (d *DynamicSelector) appSignals() *dynamicPIDSignalView {
	return &d.appSignalsView
}

// AsSelector preserves the legacy root-selector behavior.
func (d *DynamicSelector) AsSelector() services.Selector {
	return d.rootView.AsSelector()
}

// ResourceAttributesFromSelector returns resource attributes configured on a dynamic PID
// selector criteria, or nil when the selector is not from DynamicSelector.
func ResourceAttributesFromSelector(selector services.Selector) map[attr.Name]string {
	adapter, ok := selector.(*dynamicPIDCriteriaAdapter)
	if !ok || len(adapter.attrs.resourceAttributes) == 0 {
		return nil
	}
	out := make(map[attr.Name]string, len(adapter.attrs.resourceAttributes))
	for k, v := range adapter.attrs.resourceAttributes {
		out[attr.Name(k)] = v
	}
	return out
}

// dynamicPIDCriteriaAdapter implements services.Selector for a dynamically selected PID.
type dynamicPIDCriteriaAdapter struct {
	pid   app.PID
	attrs dynamicPIDAttributes
	view  *dynamicPIDSignalView
}

func newDynamicPIDCriteriaAdapter(pid app.PID, attrs dynamicPIDAttributes) *dynamicPIDCriteriaAdapter {
	return &dynamicPIDCriteriaAdapter{pid: pid, attrs: cloneAttrs(attrs)}
}

func (a *dynamicPIDCriteriaAdapter) GetName() string      { return a.attrs.serviceName }
func (a *dynamicPIDCriteriaAdapter) GetNamespace() string { return a.attrs.serviceNamespace }
func (a *dynamicPIDCriteriaAdapter) GetPath() services.StringMatcher {
	return &emptyMatcher{}
}

func (a *dynamicPIDCriteriaAdapter) GetPathRegexp() services.StringMatcher { return &emptyMatcher{} }

func (a *dynamicPIDCriteriaAdapter) GetOpenPorts() *services.IntEnum { return &services.IntEnum{} }

func (a *dynamicPIDCriteriaAdapter) GetLanguages() services.StringMatcher { return &emptyMatcher{} }

func (a *dynamicPIDCriteriaAdapter) GetPIDs() ([]app.PID, bool) {
	if a.view != nil {
		return a.view.GetPIDs()
	}
	return []app.PID{a.pid}, true
}
func (a *dynamicPIDCriteriaAdapter) GetCmdArgs() services.StringMatcher { return &emptyMatcher{} }
func (a *dynamicPIDCriteriaAdapter) IsContainersOnly() bool             { return false }
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

func (a *dynamicPIDCriteriaAdapter) GetSamplerConfig() *services.SamplerConfig { return nil }
func (a *dynamicPIDCriteriaAdapter) GetRoutesConfig() *services.CustomRoutesConfig {
	return nil
}

func (a *dynamicPIDCriteriaAdapter) MetricsConfig() perapp.SvcMetricsConfig {
	return perapp.SvcMetricsConfig{}
}

type emptyMatcher struct{}

func (emptyMatcher) IsSet() bool               { return false }
func (emptyMatcher) MatchString(_ string) bool { return false }

func emptyMetadataSeq2(_ func(string, services.StringMatcher) bool) {}

func attrsFromOptions(opts selection.DynamicOptions) dynamicPIDAttributes {
	return dynamicPIDAttributes{
		serviceName:        opts.ServiceName,
		serviceNamespace:   opts.ServiceNamespace,
		resourceAttributes: maps.Clone(opts.ResourceAttributes),
	}
}

func attrsFromEntry(entry selection.DynamicPIDEntry) dynamicPIDAttributes {
	return dynamicPIDAttributes{
		serviceName:        entry.ServiceName,
		serviceNamespace:   entry.ServiceNamespace,
		resourceAttributes: maps.Clone(entry.ResourceAttributes),
	}
}

func entryFromRecord(pid app.PID, attrs dynamicPIDAttributes) selection.DynamicPIDEntry {
	return selection.DynamicPIDEntry{
		PID:                pid,
		ServiceName:        attrs.serviceName,
		ServiceNamespace:   attrs.serviceNamespace,
		ResourceAttributes: maps.Clone(attrs.resourceAttributes),
	}
}

func cloneAttrs(attrs dynamicPIDAttributes) dynamicPIDAttributes {
	return dynamicPIDAttributes{
		serviceName:        attrs.serviceName,
		serviceNamespace:   attrs.serviceNamespace,
		resourceAttributes: maps.Clone(attrs.resourceAttributes),
	}
}

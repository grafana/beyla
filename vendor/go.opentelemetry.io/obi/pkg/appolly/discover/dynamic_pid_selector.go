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

	dynamicPIDNotifyBufferSize = 64
	dynamicPIDNotifyPendingMax = dynamicPIDNotifyBufferSize
)

// TODO: support per-signal attribute overrides; attributes are currently shared across all signals.

type dynamicPIDAttributes struct {
	serviceName        string
	serviceNamespace   string
	resourceAttributes map[string]string
}

type dynamicPIDRecord struct {
	signals dynamicPIDSignal
	attrs   dynamicPIDAttributes
}

type dynamicPIDNotifier struct {
	addedSubscribers   []*dynamicPIDSubscriber
	removedSubscribers []*dynamicPIDSubscriber

	addedPending []app.PID
	addedMu      sync.Mutex
	addedCond    *sync.Cond

	removedPending []app.PID
	removedMu      sync.Mutex
	removedCond    *sync.Cond
}

type dynamicPIDSubscriber struct {
	ctx        context.Context
	ch         chan []app.PID
	wake       chan struct{}
	done       chan struct{}
	maxPending int
	mu         sync.Mutex
	pending    []app.PID
}

func newDynamicPIDSubscriber(ctx context.Context, maxPending int) *dynamicPIDSubscriber {
	if ctx == nil {
		ctx = context.Background()
	}
	s := &dynamicPIDSubscriber{
		ctx:        ctx,
		ch:         make(chan []app.PID, dynamicPIDNotifyBufferSize),
		wake:       make(chan struct{}, 1),
		done:       make(chan struct{}),
		maxPending: maxPending,
	}
	go s.run()
	return s
}

func (s *dynamicPIDSubscriber) notify(batch []app.PID) {
	select {
	case <-s.ctx.Done():
		return
	default:
	}

	// Queue on the subscriber so a full subscriber channel cannot block notifier fan-out.
	s.mu.Lock()
	for _, pid := range batch {
		if s.maxPending > 0 && len(s.pending) == s.maxPending {
			break
		}
		s.pending = append(s.pending, pid)
	}
	s.mu.Unlock()

	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *dynamicPIDSubscriber) run() {
	defer close(s.done)
	defer close(s.ch)

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.wake:
			for {
				batch := s.takePending()
				if len(batch) == 0 {
					break
				}
				select {
				case s.ch <- batch:
				case <-s.ctx.Done():
					return
				}
			}
		}
	}
}

func (s *dynamicPIDSubscriber) takePending() []app.PID {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) == 0 {
		return nil
	}

	// Send a stable batch while later notify calls append to a fresh pending queue.
	batch := slices.Clone(s.pending)
	s.pending = nil
	return batch
}

func newDynamicPIDNotifier() *dynamicPIDNotifier {
	n := &dynamicPIDNotifier{}
	n.addedCond = sync.NewCond(&n.addedMu)
	n.removedCond = sync.NewCond(&n.removedMu)
	go n.drainAdded()
	go n.drainRemoved()
	return n
}

func (n *dynamicPIDNotifier) notifyAdded(pids []app.PID) {
	if len(pids) == 0 {
		return
	}
	n.addedMu.Lock()
	n.addedPending = append(n.addedPending, pids...)
	n.addedCond.Signal()
	n.addedMu.Unlock()
}

func (n *dynamicPIDNotifier) notifyRemoved(pids []app.PID) {
	if len(pids) == 0 {
		return
	}
	n.removedMu.Lock()
	n.removedPending = append(n.removedPending, pids...)
	n.removedCond.Signal()
	n.removedMu.Unlock()
}

func (n *dynamicPIDNotifier) drainAdded() {
	for {
		n.addedMu.Lock()
		for len(n.addedPending) == 0 || len(n.addedSubscribers) == 0 {
			n.addedCond.Wait()
		}
		batch := append([]app.PID(nil), n.addedPending...)
		n.addedPending = n.addedPending[:0]
		subscribers := slices.Clone(n.addedSubscribers)
		n.addedMu.Unlock()

		for _, subscriber := range subscribers {
			subscriber.notify(batch)
		}
	}
}

func (n *dynamicPIDNotifier) drainRemoved() {
	for {
		n.removedMu.Lock()
		for len(n.removedPending) == 0 || len(n.removedSubscribers) == 0 {
			n.removedCond.Wait()
		}
		batch := append([]app.PID(nil), n.removedPending...)
		n.removedPending = n.removedPending[:0]
		subscribers := slices.Clone(n.removedSubscribers)
		n.removedMu.Unlock()

		for _, subscriber := range subscribers {
			subscriber.notify(batch)
		}
	}
}

func (n *dynamicPIDNotifier) removeAddedSubscriber(subscriber *dynamicPIDSubscriber) {
	n.addedMu.Lock()
	n.addedSubscribers = slices.DeleteFunc(n.addedSubscribers, func(ch *dynamicPIDSubscriber) bool {
		return ch == subscriber
	})
	n.addedMu.Unlock()
}

func (n *dynamicPIDNotifier) removeRemovedSubscriber(subscriber *dynamicPIDSubscriber) {
	n.removedMu.Lock()
	n.removedSubscribers = slices.DeleteFunc(n.removedSubscribers, func(ch *dynamicPIDSubscriber) bool {
		return ch == subscriber
	})
	n.removedMu.Unlock()
}

func (n *dynamicPIDNotifier) addedNotify() <-chan []app.PID {
	subscriber := newDynamicPIDSubscriber(context.Background(), dynamicPIDNotifyPendingMax)
	n.addedMu.Lock()
	n.addedSubscribers = append(n.addedSubscribers, subscriber)
	n.addedCond.Signal()
	n.addedMu.Unlock()
	return subscriber.ch
}

func (n *dynamicPIDNotifier) addedNotifyContext(ctx context.Context) <-chan []app.PID {
	subscriber := newDynamicPIDSubscriber(ctx, 0)
	n.addedMu.Lock()
	n.addedSubscribers = append(n.addedSubscribers, subscriber)
	n.addedCond.Signal()
	n.addedMu.Unlock()

	go func() {
		<-subscriber.done
		n.removeAddedSubscriber(subscriber)
	}()
	return subscriber.ch
}

func (n *dynamicPIDNotifier) removedNotify() <-chan []app.PID {
	subscriber := newDynamicPIDSubscriber(context.Background(), dynamicPIDNotifyPendingMax)
	n.removedMu.Lock()
	n.removedSubscribers = append(n.removedSubscribers, subscriber)
	n.removedCond.Signal()
	n.removedMu.Unlock()
	return subscriber.ch
}

func (n *dynamicPIDNotifier) removedNotifyContext(ctx context.Context) <-chan []app.PID {
	subscriber := newDynamicPIDSubscriber(ctx, 0)
	n.removedMu.Lock()
	n.removedSubscribers = append(n.removedSubscribers, subscriber)
	n.removedCond.Signal()
	n.removedMu.Unlock()

	go func() {
		<-subscriber.done
		n.removeRemovedSubscriber(subscriber)
	}()
	return subscriber.ch
}

type dynamicPIDSignalView struct {
	parent   *DynamicPIDSelector
	mask     dynamicPIDSignal
	notifier *dynamicPIDNotifier
}

func (v *dynamicPIDSignalView) AddPIDs(pids ...uint32) {
	v.parent.addSignals(v.mask, nil, pids...)
}

func (v *dynamicPIDSignalView) AddPID(pid uint32, opts selection.DynamicPIDOptions) {
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

// DynamicPIDSelector holds one runtime selector object with per-signal PID views. The root Add/Remove
// methods preserve legacy behavior by applying to all supported signals.
type DynamicPIDSelector struct {
	mu    sync.RWMutex
	byPID map[app.PID]dynamicPIDRecord

	fileInfoMu        sync.RWMutex
	fileInfoByPID     map[app.PID]*exec.FileInfo
	onFileInfoUpdated func(*exec.FileInfo)
	attrsUpdatedCh    chan app.PID

	rootView           dynamicPIDSignalView
	tracesView         dynamicPIDSignalView
	appMetricsView     dynamicPIDSignalView
	networkMetricsView dynamicPIDSignalView
	statsMetricsView   dynamicPIDSignalView
	appSignalsView     dynamicPIDSignalView
}

var _ selection.MultiSignalPIDSelector = (*DynamicPIDSelector)(nil)

func newDynamicPIDSignalView(parent *DynamicPIDSelector, mask dynamicPIDSignal) dynamicPIDSignalView {
	return dynamicPIDSignalView{
		parent:   parent,
		mask:     mask,
		notifier: newDynamicPIDNotifier(),
	}
}

// NewDynamicPIDSelector creates a new selector whose root Add/Remove methods apply to all signals.
func NewDynamicPIDSelector() *DynamicPIDSelector {
	d := &DynamicPIDSelector{
		byPID:          map[app.PID]dynamicPIDRecord{},
		fileInfoByPID:  map[app.PID]*exec.FileInfo{},
		attrsUpdatedCh: make(chan app.PID, 64),
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
func (d *DynamicPIDSelector) SetOnFileInfoUpdated(fn func(*exec.FileInfo)) {
	d.fileInfoMu.Lock()
	d.onFileInfoUpdated = fn
	d.fileInfoMu.Unlock()
}

// AttrsUpdatedNotify reports PIDs whose shared attributes changed.
func (d *DynamicPIDSelector) AttrsUpdatedNotify() <-chan app.PID {
	return d.attrsUpdatedCh
}

func (d *DynamicPIDSelector) notifyAttrsUpdated(pid app.PID) {
	select {
	case d.attrsUpdatedCh <- pid:
	default:
	}
}

// RegisterFileInfo records the live FileInfo for a dynamically selected PID after instrumentation.
func (d *DynamicPIDSelector) RegisterFileInfo(pid app.PID, fi *exec.FileInfo) {
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
func (d *DynamicPIDSelector) UnregisterFileInfo(pid app.PID, fi *exec.FileInfo) {
	d.fileInfoMu.Lock()
	delete(d.fileInfoByPID, pid)
	if fi != nil {
		if owner := fi.ServiceAttrs().DynamicSelectorPID; owner != 0 {
			delete(d.fileInfoByPID, owner)
		}
	}
	d.fileInfoMu.Unlock()
}

func (d *DynamicPIDSelector) views() []*dynamicPIDSignalView {
	return []*dynamicPIDSignalView{
		&d.rootView,
		&d.tracesView,
		&d.appMetricsView,
		&d.networkMetricsView,
		&d.statsMetricsView,
		&d.appSignalsView,
	}
}

func (d *DynamicPIDSelector) addSignals(mask dynamicPIDSignal, opts *selection.DynamicPIDOptions, pids ...uint32) {
	if len(pids) == 0 {
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

		newMask := oldMask | mask
		if newMask == oldMask {
			if opts != nil {
				d.byPID[pid] = rec
				attrsUpdated = append(attrsUpdated, pid)
			}
			continue
		}
		rec.signals = newMask
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

func (d *DynamicPIDSelector) removeSignals(mask dynamicPIDSignal, pids ...uint32) {
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
		newMask := oldMask &^ mask
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

func (d *DynamicPIDSelector) getPIDs(mask dynamicPIDSignal) ([]app.PID, bool) {
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

func (d *DynamicPIDSelector) includesPID(mask dynamicPIDSignal, pid app.PID) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.byPID[pid].signals&mask != 0
}

func (d *DynamicPIDSelector) selectorForPID(pid app.PID) services.Selector {
	d.mu.RLock()
	rec, ok := d.byPID[pid]
	d.mu.RUnlock()
	if !ok {
		return nil
	}
	return newDynamicPIDCriteriaAdapter(pid, rec.attrs)
}

// GetPID returns the shared attributes for a tracked PID.
func (d *DynamicPIDSelector) GetPID(pid uint32) (selection.DynamicPIDEntry, bool) {
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
func (d *DynamicPIDSelector) SetPID(entry selection.DynamicPIDEntry) bool {
	attrs := attrsFromEntry(entry)

	d.mu.Lock()
	rec, ok := d.byPID[entry.PID]
	if !ok {
		d.mu.Unlock()
		return false
	}
	d.byPID[entry.PID] = dynamicPIDRecord{
		signals: rec.signals,
		attrs:   attrs,
	}
	d.mu.Unlock()

	d.applyAttrsToInstrumented(entry.PID, attrs)
	d.notifyAttrsUpdated(entry.PID)
	return true
}

func (d *DynamicPIDSelector) applyAttrsToInstrumented(pid app.PID, attrs dynamicPIDAttributes) {
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
func (d *DynamicPIDSelector) AddPID(pid uint32, opts selection.DynamicPIDOptions) {
	d.rootView.AddPID(pid, opts)
}

// AddPIDs adds PIDs to all supported signals (legacy root behavior).
func (d *DynamicPIDSelector) AddPIDs(pids ...uint32) {
	d.rootView.AddPIDs(pids...)
}

// RemovePIDs removes PIDs from all supported signals (legacy root behavior).
func (d *DynamicPIDSelector) RemovePIDs(pids ...uint32) {
	d.rootView.RemovePIDs(pids...)
}

// GetPIDs returns PIDs selected for any supported signal.
func (d *DynamicPIDSelector) GetPIDs() ([]app.PID, bool) {
	return d.rootView.GetPIDs()
}

// IncludesPID reports whether pid is selected for any supported signal.
func (d *DynamicPIDSelector) IncludesPID(pid app.PID) bool {
	return d.rootView.IncludesPID(pid)
}

// AddedPIDsNotify returns the channel on which PIDs are sent when they enter the root view.
func (d *DynamicPIDSelector) AddedPIDsNotify() <-chan []app.PID {
	return d.rootView.AddedPIDsNotify()
}

func (d *DynamicPIDSelector) AddedPIDsNotifyContext(ctx context.Context) <-chan []app.PID {
	return d.rootView.AddedPIDsNotifyContext(ctx)
}

// RemovedNotify returns the channel on which PIDs are sent when they leave the root view.
func (d *DynamicPIDSelector) RemovedNotify() <-chan []app.PID {
	return d.rootView.RemovedNotify()
}

func (d *DynamicPIDSelector) RemovedNotifyContext(ctx context.Context) <-chan []app.PID {
	return d.rootView.RemovedNotifyContext(ctx)
}

// Traces returns the mutable selector view for trace signals.
func (d *DynamicPIDSelector) Traces() selection.MutablePIDSelector {
	return &d.tracesView
}

// AppMetrics returns the mutable selector view for application metrics signals.
func (d *DynamicPIDSelector) AppMetrics() selection.MutablePIDSelector {
	return &d.appMetricsView
}

// NetworkMetrics returns the mutable selector view for network metrics signals.
func (d *DynamicPIDSelector) NetworkMetrics() selection.MutablePIDSelector {
	return &d.networkMetricsView
}

// StatsMetrics returns the mutable selector view for stats metrics signals.
func (d *DynamicPIDSelector) StatsMetrics() selection.MutablePIDSelector {
	return &d.statsMetricsView
}

func (d *DynamicPIDSelector) appSignals() *dynamicPIDSignalView {
	return &d.appSignalsView
}

// AsSelector preserves the legacy root-selector behavior.
func (d *DynamicPIDSelector) AsSelector() services.Selector {
	return d.rootView.AsSelector()
}

// ResourceAttributesFromSelector returns resource attributes configured on a dynamic PID
// selector criteria, or nil when the selector is not from DynamicPIDSelector.
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
func (a *dynamicPIDCriteriaAdapter) GetOpenPorts() *services.IntEnum       { return &services.IntEnum{} }
func (a *dynamicPIDCriteriaAdapter) GetLanguages() services.StringMatcher  { return &emptyMatcher{} }
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

func attrsFromOptions(opts selection.DynamicPIDOptions) dynamicPIDAttributes {
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

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"log/slog"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/simplelru"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/ebpf/timing"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/otel/idgen"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

type PIDType uint8

const (
	PIDTypeKProbes PIDType = 1 << iota
	PIDTypeGo
)

// injectable functions (can be replaced in tests). It reads the
// current process namespace from the /proc filesystem. It is required to
// choose to filter traces using whether the User-space or Host-space PIDs
var readNamespacePIDs = procs.FindNamespacedPids

var pidsFilterMonoNow = timing.MonoTimeNow

// Spans are filtered as soon as the ring buffer reader parses them, at most two
// flush intervals after capture. Removed entries stay this long so those spans
// still find their process; this only bounds memory, admission is decided by
// comparing span timestamps against removedAt
const pidRemovalRetention = 5 * time.Minute

// at 1000 forks/s entries outlive discovery's default poll interval plus minimum process age
const forkedChildrenCapacity = 1 << 14

type PIDInfo struct {
	fileInfo       *exec.FileInfo
	pidTypes       PIDType
	otherKnownPids []app.PID
	// zero while the process lives; the CLOCK_MONOTONIC instant it was
	// blocked at otherwise, comparable against BPF span timestamps
	removedAt time.Duration
	// the process that held this pid before, kept while its spans may still arrive
	previous *PIDInfo
	// when that previous process was removed: older spans are not this process's
	since time.Duration
}

type forkedChildKey struct {
	ns  uint32
	pid app.PID
}

type forkedChild struct {
	fileInfo *exec.FileInfo
	pidTypes PIDType
	forkedAt time.Duration
	execAt   time.Duration
}

type ServiceFilter interface {
	AllowPID(app.PID, uint32, *exec.FileInfo, PIDType)
	BlockPID(app.PID, uint32)
	ValidPID(app.PID, uint32, PIDType) bool
	Filter(inputSpans []request.Span) []request.Span
	CurrentPIDs(PIDType) map[uint32]map[app.PID]svc.Attrs
	ProcPIDs(PIDType) []app.PID
}

// ForkedProcessTracker admits children forked before discovery polls them
type ForkedProcessTracker interface {
	AllowForkedChild(child, parent request.PidInfo, at time.Duration)
	EndForkedChild(child request.PidInfo, at time.Duration)
}

// PIDsFilter keeps a thread-safe copy of the PIDs whose traces are allowed to
// be forwarded. Its Filter method filters the request.Span instances whose
// PIDs are not in the allowed list.
type PIDsFilter struct {
	log     *slog.Logger
	current map[uint32]map[app.PID]PIDInfo
	// live processes by the pid AllowPID received, which OBI's /proc numbers
	// uniquely; unlike current, two processes' aliases cannot share a key here
	procs               map[app.PID]PIDType
	mux                 *sync.RWMutex
	ignoreOtel          bool
	ignoreOtelSpan      bool
	defaultOtlpGRPCPort int
	metrics             imetrics.Reporter
	// readers only Peek it under the read lock: Get would reorder it
	forked *simplelru.LRU[forkedChildKey, forkedChild]
}

func NewPIDsFilter(c *services.DiscoveryConfig, log *slog.Logger, metrics imetrics.Reporter) *PIDsFilter {
	// only fails for a non-positive size
	forked, _ := simplelru.NewLRU[forkedChildKey, forkedChild](forkedChildrenCapacity, nil)
	return &PIDsFilter{
		log:                 log,
		current:             map[uint32]map[app.PID]PIDInfo{},
		procs:               map[app.PID]PIDType{},
		mux:                 &sync.RWMutex{},
		ignoreOtel:          c.ExcludeOTelInstrumentedServices,
		ignoreOtelSpan:      c.ExcludeOTelInstrumentedServicesSpanMetrics,
		defaultOtlpGRPCPort: c.DefaultOtlpGRPCPort,
		metrics:             metrics,
		forked:              forked,
	}
}

func (pf *PIDsFilter) AllowPID(pid app.PID, ns uint32, fi *exec.FileInfo, pidType PIDType) {
	pf.mux.Lock()
	defer pf.mux.Unlock()
	pf.addPID(pid, ns, fi, pidType)
}

func (pf *PIDsFilter) BlockPID(pid app.PID, ns uint32) {
	pf.mux.Lock()
	defer pf.mux.Unlock()
	pf.removePID(pid, ns)
}

func (pf *PIDsFilter) ValidPID(userPID app.PID, ns uint32, pidType PIDType) bool {
	pf.mux.RLock()
	defer pf.mux.RUnlock()

	if ns, nsExists := pf.current[ns]; nsExists {
		if info, pidExists := ns[userPID]; pidExists {
			// any generation still draining keeps its tracer type valid, so its
			// last events are parsed; Filter then picks the generation by time
			for g := &info; g != nil; g = g.previous {
				if g.pidTypes&pidType != 0 {
					return true
				}
			}
		}
	}

	child, ok := pf.forked.Peek(forkedChildKey{ns: ns, pid: userPID})
	return ok && child.pidTypes&pidType != 0
}

// The generation of the process that was alive at the given instant, nil when
// there is none: the instant is after the last known process, or before the
// ones still kept
func generationAt(info *PIDInfo, at int64) *PIDInfo {
	for g := info; g != nil; g = g.previous {
		if g.removedAt != 0 && at > int64(g.removedAt) {
			return nil
		}
		if g.since == 0 || at > int64(g.since) {
			return g
		}
	}
	return nil
}

func (c *forkedChild) owns(span *request.Span) bool {
	if span.End <= int64(c.forkedAt) || c.execAt != 0 && span.End > int64(c.execAt) {
		return false
	}
	// a child discovery hasn't registered by then never will be
	return span.End-int64(c.forkedAt) <= int64(pidRemovalRetention)
}

func expired(info *PIDInfo, now time.Duration) bool {
	return info.removedAt != 0 && now-info.removedAt > pidRemovalRetention
}

func (pf *PIDsFilter) CurrentPIDs(t PIDType) map[uint32]map[app.PID]svc.Attrs {
	pf.mux.RLock()
	defer pf.mux.RUnlock()
	cp := map[uint32]map[app.PID]svc.Attrs{}

	for k, v := range pf.current {
		cVal := map[app.PID]svc.Attrs{}
		for kv, vv := range v {
			if vv.pidTypes&t != 0 && vv.removedAt == 0 {
				cVal[kv] = vv.fileInfo.UnsafeServiceAttrs()
			}
		}
		cp[k] = cVal
	}

	return cp
}

// ProcPIDs returns one pid per live process of type t: the pid OBI's /proc
// numbers it with, which is the one AllowPID received.
func (pf *PIDsFilter) ProcPIDs(t PIDType) []app.PID {
	pf.mux.RLock()
	defer pf.mux.RUnlock()

	var pids []app.PID
	for pid, types := range pf.procs {
		if types&t != 0 {
			pids = append(pids, pid)
		}
	}

	return pids
}

func (pf *PIDsFilter) normalizeTraceContext(span *request.Span) {
	if !span.TraceID.IsValid() {
		span.TraceID = idgen.RandomTraceID()
		span.TraceFlags = 1
	}
	if !span.SpanID.IsValid() {
		span.SpanID = idgen.RandomSpanID()
	}
}

func (pf *PIDsFilter) Filter(inputSpans []request.Span) []request.Span {
	pf.mux.RLock()
	defer pf.mux.RUnlock()
	// todo: adaptive presizing as a function of the historical percentage
	// of filtered spans
	outputSpans := make([]request.Span, 0, len(inputSpans))
	for i := range inputSpans {
		span := &inputSpans[i]

		fileInfo := pf.fileInfoFor(span)
		if fileInfo == nil {
			continue
		}
		if pf.ignoreOtel {
			pf.checkIfExportsOTel(fileInfo, span, pf.defaultOtlpGRPCPort)
		}
		if pf.ignoreOtelSpan {
			pf.checkIfExportsOTelSpanMetrics(fileInfo, span, pf.defaultOtlpGRPCPort)
		}
		// Must use the unsafe version to avoid massive memory pressure here.
		inputSpans[i].Service = fileInfo.UnsafeServiceAttrs()
		pf.normalizeTraceContext(&inputSpans[i])
		outputSpans = append(outputSpans, inputSpans[i])
	}

	if len(outputSpans) != len(inputSpans) {
		pf.log.Debug("filtered spans from processes that did not match discovery",
			"function", "PIDsFilter.Filter", "inLen", len(inputSpans), "outLen", len(outputSpans),
			"pids", pf.current,
		)
	}
	return outputSpans
}

func (pf *PIDsFilter) fileInfoFor(span *request.Span) *exec.FileInfo {
	// We first confirm that the current namespace seen by BPF is tracked by OBI.
	// If the namespace exist, we confirm that we are tracking the user PID that OBI
	// saw. We don't check for the host pid, because we can't be sure of the number
	// of container layers. The Host PID is always the outer most layer.
	if info, pidExists := pf.current[span.Pid.Namespace][span.Pid.UserPID]; pidExists {
		if gen := generationAt(&info, span.End); gen != nil {
			return gen.fileInfo
		}
	}

	child, ok := pf.forked.Peek(forkedChildKey{ns: span.Pid.Namespace, pid: span.Pid.UserPID})
	if ok && child.owns(span) {
		return child.fileInfo
	}
	return nil
}

func (pf *PIDsFilter) addPID(pid app.PID, nsid uint32, fi *exec.FileInfo, t PIDType) {
	ns, nsExists := pf.current[nsid]
	if !nsExists {
		ns = make(map[app.PID]PIDInfo)
		pf.current[nsid] = ns
	}

	allPids, err := readNamespacePIDs(pid)
	if err != nil {
		pf.log.Debug("Error looking up namespaced pids", "pid", pid, "error", err)
		return
	}

	pf.procs[pid] |= t

	for _, p := range allPids {
		// discovery takes over from the fork event
		pf.forked.Remove(forkedChildKey{ns: nsid, pid: p})
		pidInfo := ns[p]
		if pidInfo.removedAt != 0 {
			// a reused pid starts a new generation; the old one is kept, not
			// inherited, so its late spans still get its own attributes
			previous := pidInfo
			pidInfo = PIDInfo{previous: &previous, since: previous.removedAt}
		}
		pidInfo.fileInfo = fi
		pidInfo.pidTypes |= t
		pidInfo.otherKnownPids = allPids
		ns[p] = pidInfo
	}
}

func (pf *PIDsFilter) removePID(pid app.PID, nsid uint32) {
	delete(pf.procs, pid)

	ns, nsExists := pf.current[nsid]
	if !nsExists {
		return
	}

	now := pidsFilterMonoNow()
	markAsRemoved := func(p app.PID) {
		if info, ok := ns[p]; ok && info.removedAt == 0 {
			info.removedAt = now
			ns[p] = info
		}
	}

	if pidInfo, pidExists := ns[pid]; pidExists {
		for _, otherPid := range pidInfo.otherKnownPids {
			markAsRemoved(otherPid)
		}
	}
	markAsRemoved(pid)

	pf.pruneExpired()
}

// AllowForkedChild files a forked child's spans under its parent until discovery registers it
func (pf *PIDsFilter) AllowForkedChild(child, parent request.PidInfo, at time.Duration) {
	pf.mux.Lock()
	defer pf.mux.Unlock()

	// grandchildren never pass the BPF filter, which only checks the parent
	parentInfo, ok := pf.current[parent.Namespace][parent.UserPID]
	if !ok {
		return
	}
	// discovery may have removed the parent, or given its pid to another process, since it forked
	forker := generationAt(&parentInfo, int64(at))
	if forker == nil {
		return
	}

	key := forkedChildKey{ns: child.Namespace, pid: child.UserPID}
	pf.forked.Add(key, forkedChild{fileInfo: forker.fileInfo, pidTypes: forker.pidTypes, forkedAt: at})
}

// EndForkedChild stops filing the child under its parent: after exec it runs another program
func (pf *PIDsFilter) EndForkedChild(child request.PidInfo, at time.Duration) {
	pf.mux.Lock()
	defer pf.mux.Unlock()

	key := forkedChildKey{ns: child.Namespace, pid: child.UserPID}
	forked, ok := pf.forked.Peek(key)
	if !ok || forked.execAt != 0 {
		return
	}
	forked.execAt = at
	pf.forked.Add(key, forked)
}

// RegisterProcessEventHandlers feeds fork and exec events to a filter that tracks forked children
func RegisterProcessEventHandlers(ctx *EBPFEventContext, filter ServiceFilter) {
	tracker, ok := filter.(ForkedProcessTracker)
	if !ok {
		return
	}

	handle := func(record *ringbuf.Record) error {
		return handleProcessEvent(record, tracker)
	}
	ctx.RegisterInternalEventHandler(EventTypeProcessFork, handle)
	ctx.RegisterInternalEventHandler(EventTypeProcessExec, handle)
}

func handleProcessEvent(record *ringbuf.Record, tracker ForkedProcessTracker) error {
	event, err := ReinterpretCast[ProcessEvent](record.RawSample)
	if err != nil {
		return err
	}

	pid := request.PidInfo{HostPID: app.PID(event.Pid.HostPid), UserPID: app.PID(event.Pid.UserPid), Namespace: event.Pid.Ns}
	at := time.Duration(event.Ts)
	if event.Type == EventTypeProcessFork {
		parent := request.PidInfo{HostPID: app.PID(event.Parent.HostPid), UserPID: app.PID(event.Parent.UserPid), Namespace: event.Parent.Ns}
		tracker.AllowForkedChild(pid, parent, at)
	} else {
		tracker.EndForkedChild(pid, at)
	}

	return nil
}

// callers must hold the write lock
func (pf *PIDsFilter) pruneExpired() {
	now := pidsFilterMonoNow()
	for nsid, ns := range pf.current {
		for pid, info := range ns {
			if expired(&info, now) {
				delete(ns, pid)
				continue
			}
			// older generations were removed earlier: cut the chain at the first expired one
			for g := &info; g.previous != nil; g = g.previous {
				if expired(g.previous, now) {
					g.previous = nil
					break
				}
			}
			ns[pid] = info
		}
		if len(ns) == 0 {
			delete(pf.current, nsid)
		}
	}
}

// IdentityPidsFilter is a PIDsFilter that does not filter anything. It is feasible
// for concrete cases like GPU tracer
type IdentityPidsFilter struct{}

func (pf *IdentityPidsFilter) AllowPID(_ app.PID, _ uint32, _ *exec.FileInfo, _ PIDType) {}

func (pf *IdentityPidsFilter) BlockPID(_ app.PID, _ uint32) {}

func (pf *IdentityPidsFilter) ValidPID(_ app.PID, _ uint32, _ PIDType) bool {
	return true
}

func (pf *IdentityPidsFilter) CurrentPIDs(_ PIDType) map[uint32]map[app.PID]svc.Attrs {
	return nil
}

func (pf *IdentityPidsFilter) ProcPIDs(_ PIDType) []app.PID {
	return nil
}

func (pf *IdentityPidsFilter) Filter(inputSpans []request.Span) []request.Span {
	return inputSpans
}

func (pf *PIDsFilter) checkIfExportsOTel(fi *exec.FileInfo, span *request.Span, defaultOtlpGRPCPort int) {
	if span.IsExportMetricsSpan(defaultOtlpGRPCPort) && fi.EnsureExportsOTelMetrics() {
		pf.reportAvoidedService(fi, "metrics")
	} else if span.IsExportTracesSpan(defaultOtlpGRPCPort) && fi.EnsureExportsOTelTraces() {
		pf.reportAvoidedService(fi, "traces")
	}
}

func (pf *PIDsFilter) checkIfExportsOTelSpanMetrics(fi *exec.FileInfo, span *request.Span, defaultOtlpGRPCPort int) {
	if span.IsExportTracesSpan(defaultOtlpGRPCPort) && fi.EnsureExportsOTelMetricsSpan() {
		pf.reportAvoidedService(fi, "metrics_span")
	}
}

func (pf *PIDsFilter) reportAvoidedService(fi *exec.FileInfo, telemetryType string) {
	if pf.metrics == nil || imetrics.IsBuiltinNoopReporter(pf.metrics) {
		return
	}

	snap := fi.ServiceAttrs()
	serviceName := snap.UID.Name
	serviceNamespace := snap.UID.Namespace
	serviceInstance := snap.UID.Instance

	switch telemetryType {
	case "metrics", "metrics_span":
		pf.metrics.AvoidInstrumentationMetrics(serviceName, serviceNamespace, serviceInstance)
	case "traces":
		pf.metrics.AvoidInstrumentationTraces(serviceName, serviceNamespace, serviceInstance)
	}
}

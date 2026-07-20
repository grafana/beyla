// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"log/slog"
	"sync"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
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

type PIDInfo struct {
	fileInfo       *exec.FileInfo
	pidTypes       PIDType
	otherKnownPids []app.PID
}

type ServiceFilter interface {
	AllowPID(app.PID, uint32, *exec.FileInfo, PIDType)
	BlockPID(app.PID, uint32)
	ValidPID(app.PID, uint32, PIDType) bool
	Filter(inputSpans []request.Span) []request.Span
	CurrentPIDs(PIDType) map[uint32]map[app.PID]svc.Attrs
}

// PIDsFilter keeps a thread-safe copy of the PIDs whose traces are allowed to
// be forwarded. Its Filter method filters the request.Span instances whose
// PIDs are not in the allowed list.
type PIDsFilter struct {
	log                 *slog.Logger
	current             map[uint32]map[app.PID]PIDInfo
	mux                 *sync.RWMutex
	ignoreOtel          bool
	ignoreOtelSpan      bool
	defaultOtlpGRPCPort int
	metrics             imetrics.Reporter
}

func NewPIDsFilter(c *services.DiscoveryConfig, log *slog.Logger, metrics imetrics.Reporter) *PIDsFilter {
	return &PIDsFilter{
		log:                 log,
		current:             map[uint32]map[app.PID]PIDInfo{},
		mux:                 &sync.RWMutex{},
		ignoreOtel:          c.ExcludeOTelInstrumentedServices,
		ignoreOtelSpan:      c.ExcludeOTelInstrumentedServicesSpanMetrics,
		defaultOtlpGRPCPort: c.DefaultOtlpGRPCPort,
		metrics:             metrics,
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
			return info.pidTypes&pidType != 0
		}
	}

	return false
}

func (pf *PIDsFilter) CurrentPIDs(t PIDType) map[uint32]map[app.PID]svc.Attrs {
	pf.mux.RLock()
	defer pf.mux.RUnlock()
	cp := map[uint32]map[app.PID]svc.Attrs{}

	for k, v := range pf.current {
		cVal := map[app.PID]svc.Attrs{}
		for kv, vv := range v {
			if vv.pidTypes&t != 0 {
				cVal[kv] = vv.fileInfo.ServiceAttrs()
			}
		}
		cp[k] = cVal
	}

	return cp
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

		// We first confirm that the current namespace seen by BPF is tracked by OBI
		ns, nsExists := pf.current[span.Pid.Namespace]

		if !nsExists {
			continue
		}

		// If the namespace exist, we confirm that we are tracking the user PID that OBI
		// saw. We don't check for the host pid, because we can't be sure of the number
		// of container layers. The Host PID is always the outer most layer.
		if info, pidExists := ns[span.Pid.UserPID]; pidExists {
			if pf.ignoreOtel {
				pf.checkIfExportsOTel(info.fileInfo, span, pf.defaultOtlpGRPCPort)
			}
			if pf.ignoreOtelSpan {
				pf.checkIfExportsOTelSpanMetrics(info.fileInfo, span, pf.defaultOtlpGRPCPort)
			}
			inputSpans[i].Service = info.fileInfo.ServiceAttrs()
			pf.normalizeTraceContext(&inputSpans[i])
			outputSpans = append(outputSpans, inputSpans[i])
		}
	}

	if len(outputSpans) != len(inputSpans) {
		pf.log.Debug("filtered spans from processes that did not match discovery",
			"function", "PIDsFilter.Filter", "inLen", len(inputSpans), "outLen", len(outputSpans),
			"pids", pf.current,
		)
	}
	return outputSpans
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

	for _, p := range allPids {
		pidInfo := ns[p]
		pidInfo.fileInfo = fi
		pidInfo.pidTypes |= t
		pidInfo.otherKnownPids = allPids
		ns[p] = pidInfo
	}
}

func (pf *PIDsFilter) removePID(pid app.PID, nsid uint32) {
	ns, nsExists := pf.current[nsid]
	if !nsExists {
		return
	}

	if pidInfo, pidExists := ns[pid]; pidExists {
		for _, otherPid := range pidInfo.otherKnownPids {
			delete(ns, otherPid)
		}
	}

	delete(ns, pid)
	if len(ns) == 0 {
		delete(pf.current, nsid)
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

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"log/slog"
	"sync"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/otel/idgen"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

type PIDType uint8

const (
	PIDTypeKProbes PIDType = iota + 1
	PIDTypeGo
)

// injectable functions (can be replaced in tests). It reads the
// current process namespace from the /proc filesystem. It is required to
// choose to filter traces using whether the User-space or Host-space PIDs
var readNamespacePIDs = procs.FindNamespacedPids

type PIDInfo struct {
	service        *svc.Attrs
	pidType        PIDType
	otherKnownPids []uint32
}

type ServiceFilter interface {
	AllowPID(uint32, uint32, *svc.Attrs, PIDType)
	BlockPID(uint32, uint32)
	ValidPID(uint32, uint32, PIDType) bool
	Filter(inputSpans []request.Span) []request.Span
	CurrentPIDs(PIDType) map[uint32]map[uint32]svc.Attrs
}

// PIDsFilter keeps a thread-safe copy of the PIDs whose traces are allowed to
// be forwarded. Its Filter method filters the request.Span instances whose
// PIDs are not in the allowed list.
type PIDsFilter struct {
	log                 *slog.Logger
	current             map[uint32]map[uint32]PIDInfo
	mux                 *sync.RWMutex
	ignoreOtel          bool
	ignoreOtelSpan      bool
	defaultOtlpGRPCPort int
	metrics             imetrics.Reporter
}

func newPIDsFilter(c *services.DiscoveryConfig, log *slog.Logger, metrics imetrics.Reporter) *PIDsFilter {
	return &PIDsFilter{
		log:                 log,
		current:             map[uint32]map[uint32]PIDInfo{},
		mux:                 &sync.RWMutex{},
		ignoreOtel:          c.ExcludeOTelInstrumentedServices,
		ignoreOtelSpan:      c.ExcludeOTelInstrumentedServicesSpanMetrics,
		defaultOtlpGRPCPort: c.DefaultOtlpGRPCPort,
		metrics:             metrics,
	}
}

func CommonPIDsFilter(c *services.DiscoveryConfig, metrics imetrics.Reporter) ServiceFilter {
	return newPIDsFilter(c, slog.With("component", "ebpfCommon.CommonPIDsFilter"), metrics)
}

func (pf *PIDsFilter) AllowPID(pid, ns uint32, svc *svc.Attrs, pidType PIDType) {
	pf.mux.Lock()
	defer pf.mux.Unlock()
	pf.addPID(pid, ns, svc, pidType)
}

func (pf *PIDsFilter) BlockPID(pid, ns uint32) {
	pf.mux.Lock()
	defer pf.mux.Unlock()
	pf.removePID(pid, ns)
}

func (pf *PIDsFilter) ValidPID(userPID, ns uint32, pidType PIDType) bool {
	pf.mux.RLock()
	defer pf.mux.RUnlock()

	if ns, nsExists := pf.current[ns]; nsExists {
		if info, pidExists := ns[userPID]; pidExists {
			return info.pidType == pidType
		}
	}

	return false
}

func (pf *PIDsFilter) CurrentPIDs(t PIDType) map[uint32]map[uint32]svc.Attrs {
	pf.mux.RLock()
	defer pf.mux.RUnlock()
	cp := map[uint32]map[uint32]svc.Attrs{}

	for k, v := range pf.current {
		cVal := map[uint32]svc.Attrs{}
		for kv, vv := range v {
			if vv.pidType == t {
				cVal[kv] = *vv.service
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

		// We first confirm that the current namespace seen by BPF is tracked by Beyla
		ns, nsExists := pf.current[span.Pid.Namespace]

		if !nsExists {
			continue
		}

		// If the namespace exist, we confirm that we are tracking the user PID that Beyla
		// saw. We don't check for the host pid, because we can't be sure of the number
		// of container layers. The Host PID is always the outer most layer.
		if info, pidExists := ns[span.Pid.UserPID]; pidExists {
			if pf.ignoreOtel {
				pf.checkIfExportsOTel(info.service, span, pf.defaultOtlpGRPCPort)
			}
			if pf.ignoreOtelSpan {
				pf.checkIfExportsOTelSpanMetrics(info.service, span, pf.defaultOtlpGRPCPort)
			}
			inputSpans[i].Service = *info.service
			pf.normalizeTraceContext(&inputSpans[i])
			outputSpans = append(outputSpans, inputSpans[i])
		}
	}

	if len(outputSpans) != len(inputSpans) {
		pf.log.Debug("filtered spans from processes that did not match discovery",
			"function", "PIDsFilter.Filter", "inLen", len(inputSpans), "outLen", len(outputSpans),
			"pids", pf.current, "spans", inputSpans,
		)
	}
	return outputSpans
}

func (pf *PIDsFilter) addPID(pid, nsid uint32, s *svc.Attrs, t PIDType) {
	ns, nsExists := pf.current[nsid]
	if !nsExists {
		ns = make(map[uint32]PIDInfo)
		pf.current[nsid] = ns
	}

	allPids, err := readNamespacePIDs(int32(pid))
	if err != nil {
		pf.log.Debug("Error looking up namespaced pids", "pid", pid, "error", err)
		return
	}

	for _, p := range allPids {
		ns[p] = PIDInfo{service: s, pidType: t, otherKnownPids: allPids}
	}
}

func (pf *PIDsFilter) removePID(pid, nsid uint32) {
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

func (pf *IdentityPidsFilter) AllowPID(_ uint32, _ uint32, _ *svc.Attrs, _ PIDType) {}

func (pf *IdentityPidsFilter) BlockPID(_ uint32, _ uint32) {}

func (pf *IdentityPidsFilter) ValidPID(_ uint32, _ uint32, _ PIDType) bool {
	return true
}

func (pf *IdentityPidsFilter) CurrentPIDs(_ PIDType) map[uint32]map[uint32]svc.Attrs {
	return nil
}

func (pf *IdentityPidsFilter) Filter(inputSpans []request.Span) []request.Span {
	return inputSpans
}

func (pf *PIDsFilter) checkIfExportsOTel(svc *svc.Attrs, span *request.Span, defaultOtlpGRPCPort int) {
	if !svc.ExportsOTelMetrics() && span.IsExportMetricsSpan(defaultOtlpGRPCPort) {
		svc.SetExportsOTelMetrics()
		pf.reportAvoidedService(svc, "metrics")
	} else if !svc.ExportsOTelTraces() && span.IsExportTracesSpan(defaultOtlpGRPCPort) {
		svc.SetExportsOTelTraces()
		pf.reportAvoidedService(svc, "traces")
	}
}

func (pf *PIDsFilter) checkIfExportsOTelSpanMetrics(svc *svc.Attrs, span *request.Span, defaultOtlpGRPCPort int) {
	if span.IsExportTracesSpan(defaultOtlpGRPCPort) && !svc.ExportsOTelMetricsSpan() {
		svc.SetExportsOTelMetricsSpan()
		pf.reportAvoidedService(svc, "metrics_span")
	}
}

// reportAvoidedService calls the appropriate internal metrics method based on telemetry type
func (pf *PIDsFilter) reportAvoidedService(svc *svc.Attrs, telemetryType string) {
	if _, ok := pf.metrics.(imetrics.NoopReporter); ok || pf.metrics == nil {
		return
	}

	// Extract service attributes
	serviceName := svc.UID.Name
	serviceNamespace := svc.UID.Namespace
	serviceInstance := svc.UID.Instance

	switch telemetryType {
	case "metrics":
		pf.metrics.AvoidInstrumentationMetrics(serviceName, serviceNamespace, serviceInstance)
	case "traces":
		pf.metrics.AvoidInstrumentationTraces(serviceName, serviceNamespace, serviceInstance)
	case "metrics_span":
		// For metrics_span, we call the metrics method since it's related to metrics export
		pf.metrics.AvoidInstrumentationMetrics(serviceName, serviceNamespace, serviceInstance)
	}
}

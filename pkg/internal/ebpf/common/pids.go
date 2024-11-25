package ebpfcommon

import (
	"log/slog"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/grafana/beyla/pkg/internal/exec"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
	"github.com/grafana/beyla/pkg/services"
)

type PIDType uint8

const (
	PIDTypeKProbes PIDType = iota + 1
	PIDTypeGo
)

var activePids, _ = lru.New[uint32, *svc.Attrs](1024)

// injectable functions (can be replaced in tests). It reads the
// current process namespace from the /proc filesystem. It is required to
// choose to filter traces using whether the User-space or Host-space PIDs
var readNamespacePIDs = exec.FindNamespacedPids

type PIDInfo struct {
	service *svc.Attrs
	pidType PIDType
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
	log        *slog.Logger
	current    map[uint32]map[uint32]PIDInfo
	mux        *sync.RWMutex
	detectOtel bool
}

var commonPIDsFilter *PIDsFilter
var commonLock sync.Mutex

func newPIDsFilter(c *services.DiscoveryConfig, log *slog.Logger) *PIDsFilter {
	return &PIDsFilter{
		log:        log,
		current:    map[uint32]map[uint32]PIDInfo{},
		mux:        &sync.RWMutex{},
		detectOtel: c.ExcludeOTelInstrumentedServices,
	}
}

func CommonPIDsFilter(c *services.DiscoveryConfig) ServiceFilter {
	commonLock.Lock()
	defer commonLock.Unlock()

	if c.SystemWide {
		return &IdentityPidsFilter{
			detectOTel: c.ExcludeOTelInstrumentedServices,
		}
	}

	if commonPIDsFilter == nil {
		commonPIDsFilter = newPIDsFilter(c, slog.With("component", "ebpfCommon.CommonPIDsFilter"))
	}

	return commonPIDsFilter
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
			if pf.detectOtel {
				checkIfExportsOTel(info.service, span)
			}
			inputSpans[i].Service = *info.service
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
		pf.log.Error("Error looking up namespaced pids", "pid", pid, "error", err)
		return
	}

	for _, p := range allPids {
		ns[p] = PIDInfo{service: s, pidType: t}
	}
}

func (pf *PIDsFilter) removePID(pid, nsid uint32) {
	ns, nsExists := pf.current[nsid]
	if !nsExists {
		return
	}

	delete(ns, pid)
	if len(ns) == 0 {
		delete(pf.current, nsid)
	}
}

// IdentityPidsFilter is a PIDsFilter that does not filter anything. It is feasible
// for system-wide instrumenation
type IdentityPidsFilter struct {
	detectOTel bool
}

func (pf *IdentityPidsFilter) AllowPID(_ uint32, _ uint32, _ *svc.Attrs, _ PIDType) {}

func (pf *IdentityPidsFilter) BlockPID(_ uint32, _ uint32) {}

func (pf *IdentityPidsFilter) ValidPID(_ uint32, _ uint32, _ PIDType) bool {
	return true
}

func (pf *IdentityPidsFilter) CurrentPIDs(_ PIDType) map[uint32]map[uint32]svc.Attrs {
	return nil
}

func (pf *IdentityPidsFilter) Filter(inputSpans []request.Span) []request.Span {
	for i := range inputSpans {
		s := &inputSpans[i]
		svc := serviceInfo(s.Pid.HostPID)
		if pf.detectOTel {
			checkIfExportsOTel(svc, s)
		}
		s.Service = *svc
	}
	return inputSpans
}

func serviceInfo(pid uint32) *svc.Attrs {
	cached, ok := activePids.Get(pid)
	if ok {
		return cached
	}

	name := commName(pid)
	lang := exec.FindProcLanguage(int32(pid), nil, name)
	result := svc.Attrs{UID: svc.UID{Name: name}, SDKLanguage: lang, ProcPID: int32(pid)}

	activePids.Add(pid, &result)

	return &result
}

func checkIfExportsOTel(svc *svc.Attrs, span *request.Span) {
	if span.IsExportMetricsSpan() {
		svc.SetExportsOTelMetrics()
	} else if span.IsExportTracesSpan() {
		svc.SetExportsOTelTraces()
	}
}

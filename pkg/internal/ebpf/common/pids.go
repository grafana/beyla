package ebpfcommon

import (
	"log/slog"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/grafana/beyla/pkg/internal/exec"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
)

var activePids, _ = lru.New[uint32, svc.ID](1024)

// injectable functions (can be replaced in tests). It reads the
// current process namespace from the /proc filesystem. It is required to
// choose to filter traces using whether the User-space or Host-space PIDs
var readNamespace = func(pid int32) (uint32, error) {
	return FindNamespace(pid)
}

var readNamespacePIDs = func(pid int32) ([]uint32, error) {
	return FindNamespacedPids(pid)
}

type ServiceFilter interface {
	AllowPID(uint32, svc.ID)
	BlockPID(uint32)
	Filter(inputSpans []request.Span) []request.Span
	CurrentPIDs() map[uint32]map[uint32]svc.ID
}

// PIDsFilter keeps a thread-safe copy of the PIDs whose traces are allowed to
// be forwarded. Its Filter method filters the request.Span instances whose
// PIDs are not in the allowed list.
type PIDsFilter struct {
	log     *slog.Logger
	current map[uint32]map[uint32]svc.ID
	mux     *sync.RWMutex
}

var commonPIDsFilter *PIDsFilter
var commonLock sync.Mutex

func NewPIDsFilter(log *slog.Logger) *PIDsFilter {
	return &PIDsFilter{
		log:     log,
		current: map[uint32]map[uint32]svc.ID{},
		mux:     &sync.RWMutex{},
	}
}

func CommonPIDsFilter(systemWide bool) ServiceFilter {
	commonLock.Lock()
	defer commonLock.Unlock()

	if systemWide {
		return &IdentityPidsFilter{}
	}

	if commonPIDsFilter == nil {
		commonPIDsFilter = NewPIDsFilter(slog.With("component", "ebpfCommon.CommonPIDsFilter"))
	}

	return commonPIDsFilter
}

func (pf *PIDsFilter) AllowPID(pid uint32, svc svc.ID) {
	pf.mux.Lock()
	defer pf.mux.Unlock()
	pf.addPID(pid, svc)
}

func (pf *PIDsFilter) BlockPID(pid uint32) {
	pf.mux.Lock()
	defer pf.mux.Unlock()
	pf.removePID(pid)
}

func (pf *PIDsFilter) CurrentPIDs() map[uint32]map[uint32]svc.ID {
	pf.mux.RLock()
	defer pf.mux.RUnlock()
	cp := map[uint32]map[uint32]svc.ID{}

	for k, v := range pf.current {
		cVal := map[uint32]svc.ID{}
		for kv, vv := range v {
			cVal[kv] = vv
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
		if svc, pidExists := ns[span.Pid.UserPID]; pidExists {
			inputSpans[i].ServiceID = svc
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

func (pf *PIDsFilter) addPID(pid uint32, s svc.ID) {
	nsid, err := readNamespace(int32(pid))

	if err != nil {
		pf.log.Error("Error looking up namespace for tracking PID", "pid", pid, "error", err)
		return
	}

	ns, nsExists := pf.current[nsid]
	if !nsExists {
		ns = make(map[uint32]svc.ID)
		pf.current[nsid] = ns
	}

	allPids, err := readNamespacePIDs(int32(pid))

	if err != nil {
		pf.log.Error("Error looking up namespaced pids", "pid", pid, "error", err)
		return
	}

	for _, p := range allPids {
		ns[p] = s
	}
}

func (pf *PIDsFilter) removePID(pid uint32) {
	nsid, err := readNamespace(int32(pid))

	if err != nil {
		// this will always happen on process removal, as /proc/<pid>/ns/pid won't be found
		// the code is kept here as a placeholder for a future fix (e.g. using eBPF notifications
		// to get both the PID and the nsid)
		// TODO: fix
		pf.log.Debug("Error looking up namespace for removing PID", "pid", pid, "error", err)
		return
	}

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
type IdentityPidsFilter struct{}

func (pf *IdentityPidsFilter) AllowPID(_ uint32, _ svc.ID) {}

func (pf *IdentityPidsFilter) BlockPID(_ uint32) {}

func (pf *IdentityPidsFilter) CurrentPIDs() map[uint32]map[uint32]svc.ID {
	return nil
}

func (pf *IdentityPidsFilter) Filter(inputSpans []request.Span) []request.Span {
	for i := range inputSpans {
		s := &inputSpans[i]
		s.ServiceID = serviceInfo(s.Pid.HostPID)
	}
	return inputSpans
}

func serviceInfo(pid uint32) svc.ID {
	cached, ok := activePids.Get(pid)
	if ok {
		return cached
	}

	name := commName(pid)
	lang := exec.FindProcLanguage(int32(pid), nil)
	result := svc.ID{Name: name, SDKLanguage: lang}

	activePids.Add(pid, result)

	return result
}

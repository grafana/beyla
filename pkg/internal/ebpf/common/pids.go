package ebpfcommon

import (
	"log/slog"
	"sync"

	"github.com/grafana/beyla/pkg/internal/request"
)

const updatesBufLen = 10

// injectable functions (can be replaced in tests). It reads the
// current process namespace from the /proc filesystem. It is required to
// choose to filter traces using whether the User-space or Host-space PIDs
var readNamespace = func(pid int32) (uint32, error) {
	return FindNamespace(pid)
}

var readNamespacePIDs = func(pid int32) ([]uint32, error) {
	return FindNamespacedPids(pid)
}

// NamespacedPID is a pair of coordinates to identify a Process ID.
type NamespacedPID struct {
	PIDNamespace uint32
	PID          uint32
}

// PIDsFilter keeps a thread-safe copy of the PIDs whose traces are allowed to
// be forwarded. Its Filter method filters the request.Span instances whose
// PIDs are not in the allowed list.
type PIDsFilter struct {
	log *slog.Logger
	// current namespaces and their PIDs
	current map[uint32]map[uint32]struct{}
	// currentLock provides concurrent R/W access to current
	currentLock *sync.RWMutex
	// currentSnapshot keeps an updated copy of the PID coordinates of current map, used to
	// concurrently share the information outside this PIDsFilter with thread safety.
	currentSnapshot []NamespacedPID
	queue           chan pidEvent
}

type PIDEventOp uint8

const (
	ADD PIDEventOp = iota + 1
	DEL
)

type pidEvent struct {
	pid uint32
	op  PIDEventOp
}

func NewPIDsFilter(log *slog.Logger) *PIDsFilter {
	return &PIDsFilter{
		log:         log,
		currentLock: &sync.RWMutex{},
		current:     map[uint32]map[uint32]struct{}{},
		queue:       make(chan pidEvent, updatesBufLen),
	}
}

func (pf *PIDsFilter) AllowPID(pid uint32) {
	pf.queue <- pidEvent{pid: pid, op: ADD}
}

func (pf *PIDsFilter) BlockPID(pid uint32) {
	pf.queue <- pidEvent{pid: pid, op: DEL}
}

func (pf *PIDsFilter) CurrentPIDs() []NamespacedPID {
	pf.updatePIDs()
	// first look if there is an updated snapshot of the
	// current PIDs, and build it if it does not exist
	// or it has been invalidated
	snapshot := pf.currentSnapshot
	if len(snapshot) == 0 {
		pf.currentLock.RLock()
		defer pf.currentLock.RUnlock()
		snapshot = make([]NamespacedPID, 0, len(pf.current))
		for ns, pids := range pf.current {
			for pid := range pids {
				snapshot = append(snapshot, NamespacedPID{PIDNamespace: ns, PID: pid})
			}
		}
		pf.currentSnapshot = snapshot
	}
	return snapshot
}

func (pf *PIDsFilter) Filter(inputSpans []request.Span) []request.Span {
	// todo: adaptive presizing as a function of the historical percentage
	// of filtered spans
	outputSpans := make([]request.Span, 0, len(inputSpans))
	pf.updatePIDs()
	pf.currentLock.RLock()
	defer pf.currentLock.RUnlock()
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
		if _, pidExists := ns[span.Pid.UserPID]; pidExists {
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

// update added/deleted PIDs, if any
func (pf *PIDsFilter) updatePIDs() {
	pf.currentLock.Lock()
	defer pf.currentLock.Unlock()
	for {
		select {
		case e := <-pf.queue:
			switch e.op {
			case ADD:
				// invalidate current PIDs snapshot
				pf.currentSnapshot = nil
				pf.addPID(e.pid)
			case DEL:
				// invalidate current PIDs snapshot
				pf.currentSnapshot = nil
				pf.removePID(e.pid)
			default:
				pf.log.Error("Unsupported PID operation", "op", e)
			}
		default:
			// no more updates
			return
		}
	}
}

// addPID is not thread-safe. Its invoker must ensure the synchronization.
func (pf *PIDsFilter) addPID(pid uint32) {
	nsid, err := readNamespace(int32(pid))

	if err != nil {
		pf.log.Error("Error looking up namespace for tracking PID", "pid", pid, "error", err)
		return
	}

	ns, nsExists := pf.current[nsid]
	if !nsExists {
		ns = make(map[uint32]struct{})
		pf.current[nsid] = ns
	}

	allPids, err := readNamespacePIDs(int32(pid))

	if err != nil {
		pf.log.Error("Error looking up namespaced pids", "pid", pid, "error", err)
		return
	}

	for _, p := range allPids {
		ns[p] = struct{}{}
	}
}

// removePID is not thread-safe. Its invoker must ensure the synchronization.
func (pf *PIDsFilter) removePID(pid uint32) {
	nsid, err := readNamespace(int32(pid))

	if err != nil {
		pf.log.Error("Error looking up namespace for removing PID", "pid", pid, "error", err)
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

func (pf *IdentityPidsFilter) AllowPID(_ uint32) {}

func (pf *IdentityPidsFilter) BlockPID(_ uint32) {}

func (pf *IdentityPidsFilter) CurrentPIDs() []NamespacedPID {
	return nil
}

func (pf *IdentityPidsFilter) Filter(inputSpans []request.Span) []request.Span {
	return inputSpans
}

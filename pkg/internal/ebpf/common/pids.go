package ebpfcommon

import (
	"fmt"
	"log/slog"

	"github.com/grafana/beyla/pkg/internal/request"
)

const updatesBufLen = 10

// NSPIDsMap associates any
type NSPIDsMap[T any] struct {
	nsPids map[uint32]map[uint32]T
}

func NewNSPIDsMap[T any]() NSPIDsMap[T] {
	return NSPIDsMap[T]{nsPids: make(map[uint32]map[uint32]T)}
}

// injectable functions (can be replaced in tests). It reads the
// current process namespace from the /proc filesystem. It is required to
// choose to filter traces using whether the User-space or Host-space PIDs
var readNamespace = FindNamespace
var readNamespacePIDs = FindNamespacedPids

// PIDsFilter keeps a thread-safe copy of the PIDs whose traces are allowed to
// be forwarded. Its Filter method filters the request.Span instances whose
// PIDs are not in the allowed list.
type PIDsFilter struct {
	log     *slog.Logger
	current NSPIDsMap[struct{}]
	queue   chan pidEvent
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
		log:     log,
		current: NewNSPIDsMap[struct{}](),
		queue:   make(chan pidEvent, updatesBufLen),
	}
}

func (pf *PIDsFilter) AllowPID(pid uint32) {
	pf.queue <- pidEvent{pid: pid, op: ADD}
}

func (pf *PIDsFilter) BlockPID(pid uint32) {
	pf.queue <- pidEvent{pid: pid, op: DEL}
}

func (pf *PIDsFilter) CurrentPIDs() map[uint32]map[uint32]struct{} {
	pf.updatePIDs()
	return pf.current.nsPids
}

func (pf *PIDsFilter) Filter(inputSpans []request.Span) []request.Span {
	// todo: adaptive presizing as a function of the historical percentage
	// of filtered spans
	outputSpans := make([]request.Span, 0, len(inputSpans))
	pf.updatePIDs()
	for i := range inputSpans {
		span := &inputSpans[i]

		// We first confirm that the current namespace seen by BPF is tracked by Beyla
		ns, nsExists := pf.current.nsPids[span.Pid.Namespace]

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
	for {
		select {
		case e := <-pf.queue:
			switch e.op {
			case ADD:
				if err := pf.current.AddPID(e.pid, struct{}{}); err != nil {
					pf.log.Error("setting PID namespace", "error", err)
				}
			case DEL:
				if _, err := pf.current.RemovePID(e.pid); err != nil {
					pf.log.Error("removing PID", "error", err)
				}
			default:
				pf.log.Error("Unsupported PID operation")
			}
		default:
			// no more updates
			return
		}
	}
}

func (pm *NSPIDsMap[T]) AddPID(pid uint32, val T) error {
	nsid, err := readNamespace(pid)
	if err != nil {
		return fmt.Errorf("looking up namespace for tracking PID %d: %w", pid, err)
	}
	fmt.Println("namespace for pid", pid, ":", nsid)
	ns, nsExists := pm.nsPids[nsid]
	if !nsExists {
		ns = map[uint32]T{}
		pm.nsPids[nsid] = ns
	}

	allPids, err := readNamespacePIDs(pid)

	if err != nil {
		return fmt.Errorf("PID %d, NS %d. Looking up for namespaced PIDs: %w", pid, nsid, err)
	}

	for _, p := range allPids {
		ns[p] = val
	}
	return nil
}

// RemovePID removes the PID namespace, if the PID could be removed
func (pm *NSPIDsMap[T]) RemovePID(pid uint32) (uint32, error) {
	nsid, err := readNamespace(pid)

	if err != nil {
		return 0, fmt.Errorf("looking up namespace for removing PID %d: %w", pid, err)
	}

	ns, nsExists := pm.nsPids[nsid]
	if !nsExists {
		return nsid, nil
	}

	delete(ns, pid)
	if len(ns) == 0 {
		delete(pm.nsPids, nsid)
	}
	return nsid, nil
}

func (pm *NSPIDsMap[T]) Get(namespace, pid uint32) (T, bool) {
	if pids, ok := pm.nsPids[namespace]; ok {
		if t, ok := pids[pid]; ok {
			return t, true
		}
	}
	var t T
	return t, false
}

// IdentityPidsFilter is a PIDsFilter that does not filter anything. It is feasible
// for system-wide instrumenation
type IdentityPidsFilter struct{}

func (pf *IdentityPidsFilter) AllowPID(_ uint32) {}

func (pf *IdentityPidsFilter) BlockPID(_ uint32) {}

func (pf *IdentityPidsFilter) CurrentPIDs() map[uint32]map[uint32]struct{} {
	return nil
}

func (pf *IdentityPidsFilter) Filter(inputSpans []request.Span) []request.Span {
	return inputSpans
}

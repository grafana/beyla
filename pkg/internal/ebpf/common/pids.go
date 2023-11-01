package ebpfcommon

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"github.com/grafana/beyla/pkg/internal/request"
)

const updatesBufLen = 10

// injectable function (can be replaced in tests). It reads the
// current process namespace from the /proc filesystem. It is required to
// choose to filter traces using whether the User-space or Host-space PIDs
var readNamespace = func() uint32 {
	log := slog.With("component", "ebpfcommon.readNamespace")
	dst, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", os.Getpid()))
	if err != nil {
		log.Warn("error reading pids namespace. Assuming 0", "error", err)
		return 0
	}
	ns, err := strconv.ParseUint(dst[len("pid:["):len(dst)-1], 10, 32)
	if err != nil {
		log.Warn("parsing pids string. Assuming 0", "str", dst, "error", err)
		return 0
	}

	log.Debug("fetched Beyla PID namespace", "str", dst, "value", ns)
	return uint32(ns)
}

// PIDsFilter keeps a thread-safe copy of the PIDs whose traces are allowed to
// be forwarded. Its Filter method filters the request.Span instances whose
// PIDs are not in the allowed list.
type PIDsFilter struct {
	log     *slog.Logger
	current map[uint32]map[uint32]struct{}
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
		current: map[uint32]map[uint32]struct{}{},
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
	return pf.current
}

func (pf *PIDsFilter) Filter(inputSpans []request.Span) []request.Span {
	// todo: adaptive presizing as a function of the historical percentage
	// of filtered spans
	outputSpans := make([]request.Span, 0, len(inputSpans))
	pf.updatePIDs()
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
	for {
		select {
		case e := <-pf.queue:
			switch e.op {
			case ADD:
				pf.addPID(e.pid)
			case DEL:
				pf.removePID(e.pid)
			default:
				pf.log.Error("Unsupported PID operation")
			}
		default:
			// no more updates
			return
		}
	}
}

func (pf *PIDsFilter) addPID(pid uint32) {
	nsid, err := FindNamespace(int32(pid))

	if err != nil {
		pf.log.Error("Error looking up namespace for tracking PID", "pid", pid, "error", err)
		return
	}

	ns, nsExists := pf.current[nsid]
	if !nsExists {
		ns = make(map[uint32]struct{})
		pf.current[nsid] = ns
	}

	allPids, err := FindNamespacedPids(int32(pid))

	if err != nil {
		pf.log.Error("Error looking up namespaced pids", "pid", pid, "error", err)
		return
	}

	for _, p := range allPids {
		ns[p] = struct{}{}
	}
}

func (pf *PIDsFilter) removePID(pid uint32) {
	nsid, err := FindNamespace(int32(pid))

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

func (pf *IdentityPidsFilter) CurrentPIDs() map[uint32]map[uint32]struct{} {
	return nil
}

func (pf *IdentityPidsFilter) Filter(inputSpans []request.Span) []request.Span {
	return inputSpans
}

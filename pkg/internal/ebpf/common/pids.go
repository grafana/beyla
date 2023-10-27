package ebpfcommon

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"github.com/grafana/beyla/pkg/internal/request"
)

const updatesBufLen = 10

// PIDsFilter keeps a thread-safe copy of the PIDs whose traces are allowed to
// be forwarded. Its Filter method filters the request.Span instances whose
// PIDs are not in the allowed list.
type PIDsFilter struct {
	pidNs   uint32
	log     *slog.Logger
	current map[uint32]struct{}
	added   chan uint32
	deleted chan uint32
}

func NewPIDsFilter(log *slog.Logger) *PIDsFilter {
	// WIP experiment. Don't  pay attention in the PR
	dst, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", os.Getpid()))
	if err != nil {
		slog.Error("ERRRORACO: " + err.Error())
	}
	slog.Info("PID NS dst: " + dst)
	ns, _ := strconv.ParseUint(dst[len("pid:["):len(dst)-1], 10, 32)
	return &PIDsFilter{
		pidNs:   uint32(ns),
		log:     log,
		current: map[uint32]struct{}{},
		added:   make(chan uint32, updatesBufLen),
		deleted: make(chan uint32, updatesBufLen),
	}
}

func (pf *PIDsFilter) AllowPID(pid uint32) {
	pf.added <- pid
}

func (pf *PIDsFilter) BlockPID(pid uint32) {
	pf.deleted <- pid
}

func (pf *PIDsFilter) Filter(inputSpans []request.Span) []request.Span {
	// todo: adaptive presizing as a function of the historical percentage
	// of filtered spans
	outputSpans := make([]request.Span, 0, len(inputSpans))
	pf.updatePIDs()
	for i := range inputSpans {
		// While BPF always see the processes in the same way (from the kernel-side)
		// Beyla userspace might see them differently depending on how it is operating.
		// If they are in different namespaces, the process finder will
		var pidView uint32
		if inputSpans[i].Pid.Namespace == pf.pidNs {
			// If Beyla is in the same namespace as the inspected process (in the same host,
			// or in the same Pod), they will both share the same view of the PID from
			// the userspace, so we filter according to this value.
			pidView = inputSpans[i].Pid.UserPID
		} else {
			// If Beyla is in a different namespace than the inspected process (for example,
			// in a different container with different pid cgroups),it will see the
			// same PID as the host so we need to filter traces according to it.
			pidView = inputSpans[i].Pid.HostPID
		}
		if _, ok := pf.current[pidView]; ok {
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
		case pid := <-pf.added:
			pf.current[pid] = struct{}{}
		case pid := <-pf.deleted:
			delete(pf.current, pid)
		default:
			// no more updates
			return
		}
	}
}

// IdentityPidsFilter is a PIDsFilter that does not filter anything. It is feasible
// for system-wide instrumenation
type IdentityPidsFilter struct{}

func (pf *IdentityPidsFilter) AllowPID(_ uint32) {}

func (pf *IdentityPidsFilter) BlockPID(_ uint32) {}

func (pf *IdentityPidsFilter) Filter(inputSpans []request.Span) []request.Span {
	return inputSpans
}

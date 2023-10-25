package ebpfcommon

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"github.com/grafana/beyla/pkg/internal/request"
)

const updatesBufLen = 10

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

func (pf *PIDsFilter) AddPID(pid uint32) {
	pf.added <- pid
}

// RemovePID notifies the tracer to stop accepting traces from the process
// with the provided PID. After receiving them via ringbuffer, it should
// stop discard them.
func (pf *PIDsFilter) RemovePID(pid uint32) {
	pf.deleted <- pid
}

func (pf *PIDsFilter) Filter(inputSpans []request.Span) []request.Span {
	// todo: adaptive presizing as a function of the historical percentage
	// of filtered spans
	outputSpans := make([]request.Span, 0, len(inputSpans))
	pf.updatePIDs()
	for i := range inputSpans {
		var pidView uint32
		if inputSpans[i].Pid.Namespace == pf.pidNs {
			pidView = inputSpans[i].Pid.User
		} else {
			pidView = inputSpans[i].Pid.Kernel
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

func (pf *IdentityPidsFilter) AddPID(_ uint32) {}

func (pf *IdentityPidsFilter) RemovePID(_ uint32) {}

func (pf *IdentityPidsFilter) Filter(inputSpans []request.Span) []request.Span {
	return inputSpans
}

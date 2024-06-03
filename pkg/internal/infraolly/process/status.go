package process

import (
	"log/slog"

	"github.com/grafana/beyla/pkg/internal/svc"
)

func pslog() *slog.Logger {
	return slog.With("component", "process.Collector")
}

type Status struct {
	ProcessID        int32
	Command          string
	User             string
	MemoryRSSBytes   int64
	MemoryVMSBytes   int64
	CPUPercent       float64
	CPUUserPercent   float64
	CPUSystemPercent float64
	CommandLine      string
	Status           string
	ParentProcessID  int32
	ThreadCount      int32
	FdCount          int32
	IOReadCount      uint64
	IOWriteCount     uint64
	IOReadBytes      uint64
	IOWriteBytes     uint64

	Service *svc.ID
}

func NewStatus(pid int32, svcID *svc.ID) *Status {
	return &Status{
		ProcessID: pid,
		Service:   svcID,
	}
}

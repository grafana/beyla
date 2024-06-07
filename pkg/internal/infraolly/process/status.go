package process

import (
	"log/slog"
	"strconv"
	"strings"

	"go.opentelemetry.io/otel/attribute"

	"github.com/grafana/beyla/pkg/internal/export/attributes"
	attr "github.com/grafana/beyla/pkg/internal/export/attributes/names"
	"github.com/grafana/beyla/pkg/internal/svc"
)

func pslog() *slog.Logger {
	return slog.With("component", "process.Collector")
}

// Status of a process after being harvested
type Status struct {
	ProcessID   int32
	Command     string
	CommandArgs []string
	CommandLine string
	ExecName    string
	ExecPath    string

	User             string
	MemoryRSSBytes   int64
	MemoryVMSBytes   int64
	CPUPercent       float64
	CPUUserPercent   float64
	CPUSystemPercent float64
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

// nolint:cyclop
func OTELGetters(name attr.Name) (attributes.Getter[*Status, attribute.KeyValue], bool) {
	var g attributes.Getter[*Status, attribute.KeyValue]
	switch name {
	case attr.ProcCommand:
		g = func(s *Status) attribute.KeyValue { return attribute.Key(attr.ProcCommand).String(s.Command) }
	case attr.ProcCommandLine:
		g = func(s *Status) attribute.KeyValue {
			return attribute.Key(attr.ProcCommandLine).String(s.CommandLine)
		}
	case attr.ProcExecName:
		g = func(status *Status) attribute.KeyValue {
			return attribute.Key(attr.ProcExecName).String(status.ExecName)
		}
	case attr.ProcExecPath:
		g = func(status *Status) attribute.KeyValue {
			return attribute.Key(attr.ProcExecPath).String(status.ExecPath)
		}
	case attr.ProcCommandArgs:
		g = func(status *Status) attribute.KeyValue {
			return attribute.Key(attr.ProcCommandArgs).StringSlice(status.CommandArgs)
		}
	case attr.ProcOwner:
		g = func(s *Status) attribute.KeyValue { return attribute.Key(attr.ProcOwner).String(s.User) }
	case attr.ProcParentPid:
		g = func(s *Status) attribute.KeyValue {
			return attribute.Key(attr.ProcParentPid).Int(int(s.ParentProcessID))
		}
	case attr.ProcPid:
		g = func(s *Status) attribute.KeyValue {
			return attribute.Key(attr.ProcPid).Int(int(s.ProcessID))
		}
	}
	return g, g != nil
}

// nolint:cyclop
func PromGetters(name attr.Name) (attributes.Getter[*Status, string], bool) {
	var g attributes.Getter[*Status, string]
	switch name {
	case attr.ProcCommand:
		g = func(s *Status) string { return s.Command }
	case attr.ProcCommandLine:
		g = func(s *Status) string { return s.CommandLine }
	case attr.ProcExecName:
		g = func(status *Status) string { return status.ExecName }
	case attr.ProcExecPath:
		g = func(status *Status) string { return status.ExecPath }
	case attr.ProcCommandArgs:
		g = func(status *Status) string { return strings.Join(status.CommandArgs, ",") }
	case attr.ProcOwner:
		g = func(s *Status) string { return s.User }
	case attr.ProcParentPid:
		g = func(s *Status) string { return strconv.Itoa(int(s.ParentProcessID)) }
	case attr.ProcPid:
		g = func(s *Status) string { return strconv.Itoa(int(s.ProcessID)) }
	}
	return g, g != nil
}

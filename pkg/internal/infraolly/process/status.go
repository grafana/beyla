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
	User        string
	Command     string
	CommandArgs []string
	CommandLine string
	ExecName    string
	ExecPath    string

	// Despite values below are absolute counters, the OTEL and Prometheus APIs require that
	// they are specified as deltas

	CPUTimeSystemDelta float64
	CPUTimeUserDelta   float64
	CPUTimeWaitDelta   float64

	CPUUtilisationSystem float64
	CPUUtilisationUser   float64
	CPUUtilisationWait   float64

	// delta values are used in OTEL UpDownCounters while absolute values are used in Prometheus gauges
	MemoryRSSBytes      int64
	MemoryVMSBytes      int64
	MemoryRSSBytesDelta int64
	MemoryVMSBytesDelta int64

	Status          string
	ParentProcessID int32
	ThreadCount     int32
	FdCount         int32

	IOReadCount       uint64
	IOWriteCount      uint64
	IOReadBytesDelta  uint64
	IOWriteBytesDelta uint64

	NetTxBytesDelta  int64
	NetRcvBytesDelta int64

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
	case attr.HostName:
		g = func(s *Status) attribute.KeyValue { return attribute.Key(attr.HostName).String(s.Service.HostName) }
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
	case attr.ProcCPUState, attr.ProcDiskIODir, attr.ProcNetIODir:
		// the attributes are handled explicitly by the OTEL exporter, but we need to
		// ignore them to avoid that the default case tries to report them from service metadata
	default:
		g = func(s *Status) attribute.KeyValue { return attribute.String(string(name), s.Service.Metadata[name]) }
	}
	return g, g != nil
}

// nolint:cyclop
func PromGetters(name attr.Name) (attributes.Getter[*Status, string], bool) {
	var g attributes.Getter[*Status, string]
	switch name {
	case attr.HostName:
		g = func(s *Status) string { return s.Service.HostName }
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
	case attr.ProcCPUState, attr.ProcDiskIODir, attr.ProcNetIODir:
		// the attributes are handled explicitly by the prometheus exporter, but we need to
		// ignore them to avoid that the default case tries to report them from service metadata
	default:
		g = func(s *Status) string { return s.Service.Metadata[name] }
	}
	return g, g != nil
}

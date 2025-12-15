package process

import (
	"log/slog"
	"strconv"
	"strings"

	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	attributes "go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"

	extranames "github.com/grafana/beyla/v2/pkg/export/extraattributes/names"
)

func pslog() *slog.Logger {
	return slog.With("component", "process.Collector")
}

type ID struct {
	Service *svc.Attrs

	// UID for a process. Even if the Service field has its own UID,
	// a service might have multiple processes, so Application and Process
	// will be different resources, each one with its own UID,
	// which will be the composition of Service.Instance-ProcessID
	UID svc.UID

	ProcessID       int32
	ParentProcessID int32
	User            string
	Command         string
	CommandArgs     []string
	CommandLine     string
	ExecName        string
	ExecPath        string
}

func (i *ID) GetUID() svc.UID {
	return i.UID
}

// Status of a process after being harvested
type Status struct {
	ID ID

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

	Status      string
	ThreadCount int32
	FdCount     int32

	IOReadCount       uint64
	IOWriteCount      uint64
	IOReadBytesDelta  uint64
	IOWriteBytesDelta uint64

	NetTxBytesDelta  int64
	NetRcvBytesDelta int64
}

func NewStatus(pid int32, svcID *svc.Attrs) *Status {
	return &Status{ID: ID{
		ProcessID: pid,
		Service:   svcID,
		UID: svc.UID{
			Name:      svcID.UID.Name,
			Namespace: svcID.UID.Namespace,
			Instance:  svcID.UID.Instance + ":" + strconv.Itoa(int(pid)),
		},
	}}
}

// OTELGetters is currently empty as most attributes are resource-level,
// but left as a placeholder for future attribute additions.
// nolint:cyclop
func OTELGetters(name attr.Name) (attributes.Getter[*Status, attribute.KeyValue], bool) {
	var g attributes.Getter[*Status, attribute.KeyValue]
	switch name {
	case extranames.ProcCPUMode, extranames.ProcDiskIODir, extranames.ProcNetIODir:
		// the attributes are handled explicitly by the OTEL exporter, but we need to
		// ignore them to avoid that the default case tries to report them from service metadata
	}
	return g, g != nil
}

// nolint:cyclop
func PromGetters(name attr.Name) (attributes.Getter[*Status, string], bool) {
	var g attributes.Getter[*Status, string]
	switch name {
	case attr.HostName:
		g = func(s *Status) string { return s.ID.Service.HostName }
	case extranames.ProcCommand:
		g = func(s *Status) string { return s.ID.Command }
	case extranames.ProcCommandLine:
		g = func(s *Status) string { return s.ID.CommandLine }
	case extranames.ProcExecName:
		g = func(status *Status) string { return status.ID.ExecName }
	case extranames.ProcExecPath:
		g = func(status *Status) string { return status.ID.ExecPath }
	case extranames.ProcCommandArgs:
		g = func(status *Status) string { return strings.Join(status.ID.CommandArgs, ",") }
	case extranames.ProcOwner:
		g = func(s *Status) string { return s.ID.User }
	case extranames.ProcParentPid:
		g = func(s *Status) string { return strconv.Itoa(int(s.ID.ParentProcessID)) }
	case extranames.ProcPid:
		g = func(s *Status) string { return strconv.Itoa(int(s.ID.ProcessID)) }
	case extranames.ProcCPUMode, extranames.ProcDiskIODir, extranames.ProcNetIODir:
		// the attributes are handled explicitly by the prometheus exporter, but we need to
		// ignore them to avoid that the default case tries to report them from service metadata
	case attr.Instance:
		g = func(s *Status) string { return s.ID.UID.Instance }
	case attr.Job:
		g = func(s *Status) string { return s.ID.Service.Job() }
	default:
		g = func(s *Status) string { return s.ID.Service.Metadata[name] }
	}
	return g, g != nil
}

package svc

import (
	semconv "go.opentelemetry.io/otel/semconv/v1.25.0"

	attr "github.com/grafana/beyla/pkg/export/attributes/names"
)

type InstrumentableType int

const (
	InstrumentableGolang InstrumentableType = iota + 1
	InstrumentableJava
	InstrumentableDotnet
	InstrumentablePython
	InstrumentableRuby
	InstrumentableNodejs
	InstrumentableRust
	InstrumentableGeneric
	InstrumentablePHP
)

func (it InstrumentableType) String() string {
	switch it {
	case InstrumentableGolang:
		return semconv.TelemetrySDKLanguageGo.Value.AsString()
	case InstrumentableJava:
		return semconv.TelemetrySDKLanguageJava.Value.AsString()
	case InstrumentableDotnet:
		return semconv.TelemetrySDKLanguageDotnet.Value.AsString()
	case InstrumentablePython:
		return semconv.TelemetrySDKLanguagePython.Value.AsString()
	case InstrumentableRuby:
		return semconv.TelemetrySDKLanguageRuby.Value.AsString()
	case InstrumentableNodejs:
		return semconv.TelemetrySDKLanguageNodejs.Value.AsString()
	case InstrumentableRust:
		return semconv.TelemetrySDKLanguageRust.Value.AsString()
	case InstrumentablePHP:
		return semconv.TelemetrySDKLanguagePHP.Value.AsString()
	case InstrumentableGeneric:
		return "generic"
	default:
		// if this appears, it's a bug!!
		return "unknown"
	}
}

type idFlags uint8

const (
	autoName           idFlags = 0x1
	exportsOTelMetrics idFlags = 0x2
	exportsOTelTraces  idFlags = 0x4
)

// ID stores the metadata attributes of a service/resource
// TODO: rename to svc.Attributes
type ID struct {
	// UID uniquely identifies a service instance. It is not exported
	// in the metrics or traces, but it is used to compose the InstanceID
	UID UID

	Name string
	// AutoName is true if the Name has been automatically set by Beyla (e.g. executable name when
	// the Name is empty). This will allow later refinement of the Name value (e.g. to override it
	// again with Kubernetes metadata).
	Namespace   string
	SDKLanguage InstrumentableType

	Metadata map[attr.Name]string

	// ProcPID is the PID of the instrumented process as seen by Beyla's /proc filesystem.
	// It is stored here at process discovery time, because it might differ form the
	// UserPID and HostPID fields of the request.PidInfo struct.
	ProcPID int32

	// HostName running the process. It will default to the Beyla host and will be overridden
	// by other metadata if available (e.g., Pod Name, Node Name, etc...)
	HostName string

	EnvVars map[string]string

	flags idFlags
}

func (i *ID) GetUID() UID {
	return i.UID
}

func (i *ID) String() string {
	return i.Job()
}

func (i *ID) Job() string {
	if i.Namespace != "" {
		return i.Namespace + "/" + i.Name
	}
	return i.Name
}

func (i *ID) setFlag(flag idFlags) {
	i.flags |= flag
}

func (i *ID) getFlag(flag idFlags) bool {
	return (i.flags & flag) == flag
}

func (i *ID) SetAutoName() {
	i.setFlag(autoName)
}

func (i *ID) AutoName() bool {
	return i.getFlag(autoName)
}

func (i *ID) SetExportsOTelMetrics() {
	i.setFlag(exportsOTelMetrics)
}

func (i *ID) ExportsOTelMetrics() bool {
	return i.getFlag(exportsOTelMetrics)
}

func (i *ID) SetExportsOTelTraces() {
	i.setFlag(exportsOTelTraces)
}

func (i *ID) ExportsOTelTraces() bool {
	return i.getFlag(exportsOTelTraces)
}

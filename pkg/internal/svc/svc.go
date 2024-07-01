package svc

import (
	semconv "go.opentelemetry.io/otel/semconv/v1.25.0"

	attr "github.com/grafana/beyla/pkg/internal/export/attributes/names"
)

type InstrumentableType int

const (
	InstrumentableGolang = InstrumentableType(iota)
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
		return "unknown(bug!)"
	}
}

// UID uniquely identifies a service instance
type UID string

// ID stores the metadata attributes of a service/resource
// TODO: rename to svc.Attributes
type ID struct {
	// UID might coincide with other fields (usually, Instance), but UID
	// can't be overriden by the user, so it's the only field that can be
	// used for internal differentiation of the users.
	// UID is not exported in the metrics or traces.
	UID UID

	Name string
	// AutoName is true if the Name has been automatically set by Beyla (e.g. executable name when
	// the Name is empty). This will allow later refinement of the Name value (e.g. to override it
	// again with Kubernetes metadata).
	AutoName    bool
	Namespace   string
	SDKLanguage InstrumentableType
	Instance    string

	Metadata map[attr.Name]string

	// ProcPID is the PID of the instrumented process as seen by Beyla's /proc filesystem.
	// It is stored here at process discovery time, because it might differ form the
	// UserPID and HostPID fields of the request.PidInfo struct.
	ProcPID int32

	// HostName running the process. It will default to the Beyla host and will be overridden
	// by other metadata if available (e.g., Pod Name, Node Name, etc...)
	HostName string
}

func (i *ID) String() string {
	if i.Namespace != "" {
		return i.Namespace + "/" + i.Name
	}
	return i.Name
}

package svc

import (
	semconv "go.opentelemetry.io/otel/semconv/v1.25.0"

	attr "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes/names"
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
	autoName               idFlags = 0x1
	exportsOTelMetrics     idFlags = 0x2
	exportsOTelTraces      idFlags = 0x4
	exportsOTelMetricsSpan idFlags = 0x8
)

// UID uniquely identifies a service instance across the whole system
// according to the OpenTelemetry specification: (name, namespace, instance)
type UID struct {
	Name      string
	Namespace string
	Instance  string
}

// Attrs stores the metadata attributes of a service/resource
type Attrs struct {
	// Instance uniquely identifies a service instance. It is not exported
	// in the metrics or traces, but it is used to compose the Instance
	UID UID

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

func (i *Attrs) GetUID() UID {
	return i.UID
}

func (i *Attrs) String() string {
	return i.Job()
}

func (i *Attrs) Job() string {
	if i.UID.Namespace != "" {
		return i.UID.Namespace + "/" + i.UID.Name
	}
	return i.UID.Name
}

func (i *Attrs) setFlag(flag idFlags) {
	i.flags |= flag
}

func (i *Attrs) getFlag(flag idFlags) bool {
	return (i.flags & flag) == flag
}

func (i *Attrs) SetAutoName() {
	i.setFlag(autoName)
}

func (i *Attrs) AutoName() bool {
	return i.getFlag(autoName)
}

func (i *Attrs) SetExportsOTelMetrics() {
	i.setFlag(exportsOTelMetrics)
}

func (i *Attrs) ExportsOTelMetrics() bool {
	return i.getFlag(exportsOTelMetrics)
}

func (i *Attrs) SetExportsOTelMetricsSpan() {
	i.setFlag(exportsOTelMetricsSpan)
}

func (i *Attrs) ExportsOTelMetricsSpan() bool {
	return i.getFlag(exportsOTelMetricsSpan)
}

func (i *Attrs) SetExportsOTelTraces() {
	i.setFlag(exportsOTelTraces)
}

func (i *Attrs) ExportsOTelTraces() bool {
	return i.getFlag(exportsOTelTraces)
}

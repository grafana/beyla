package svc

import semconv "go.opentelemetry.io/otel/semconv/v1.19.0"

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
		return "rust"
	case InstrumentableGeneric:
		return "generic"
	default:
		return "unknown(bug!)"
	}
}

// ID stores the coordinates that uniquely identifies a service:
// its name and optionally a namespace
type ID struct {
	Name string
	// AutoName is true if the Name has been automatically set by Beyla (e.g. executable name when
	// the Name is empty). This will allow later refinement of the Name value (e.g. to override it
	// again with Kubernetes metadata).
	AutoName    bool
	Namespace   string
	SDKLanguage InstrumentableType
	Instance    string
}

func (i *ID) String() string {
	if i.Namespace != "" {
		return i.Namespace + "/" + i.Name
	}
	return i.Name
}

package svc

import semconv "go.opentelemetry.io/otel/semconv/v1.17.0"

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
	Name        string
	Namespace   string
	SDKLanguage InstrumentableType
}

func (i *ID) String() string {
	if i.Namespace != "" {
		return i.Namespace + "/" + i.Name
	}
	return i.Name
}

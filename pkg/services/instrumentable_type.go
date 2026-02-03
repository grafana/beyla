package services

import (
	"fmt"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
)

// InstrumentableType is a wrapper around svc.InstrumentableType that adds
// unmarshaling capabilities for configuration parsing.
// Once we add this functionality in OBI, we can remove this wrapper type.
type InstrumentableType struct {
	svc.InstrumentableType
}

func (it *InstrumentableType) UnmarshalText(text []byte) error {
	lang := strings.ToLower(string(text))

	switch lang {
	case "java":
		it.InstrumentableType = svc.InstrumentableJava
	case "dotnet":
		it.InstrumentableType = svc.InstrumentableDotnet
	case "nodejs":
		it.InstrumentableType = svc.InstrumentableNodejs
	case "go", "golang":
		it.InstrumentableType = svc.InstrumentableGolang
	case "python":
		it.InstrumentableType = svc.InstrumentablePython
	case "ruby":
		it.InstrumentableType = svc.InstrumentableRuby
	case "rust":
		it.InstrumentableType = svc.InstrumentableRust
	case "php":
		it.InstrumentableType = svc.InstrumentablePHP
	case "generic":
		it.InstrumentableType = svc.InstrumentableGeneric
	default:
		return fmt.Errorf("unknown SDK language: %s (supported: java, dotnet, nodejs, go, python, ruby, rust, php, generic)", lang)
	}

	return nil
}

func (it InstrumentableType) MarshalText() ([]byte, error) {
	return []byte(it.String()), nil
}

// ParseInstrumentableType converts a string to svc.InstrumentableType.
// This is a convenience function for interfacing with OBI.
func ParseInstrumentableType(lang string) (svc.InstrumentableType, error) {
	var it InstrumentableType
	if err := it.UnmarshalText([]byte(lang)); err != nil {
		return 0, err
	}
	return it.InstrumentableType, nil
}

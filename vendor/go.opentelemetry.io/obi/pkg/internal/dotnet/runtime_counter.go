// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet // import "go.opentelemetry.io/obi/pkg/internal/dotnet"

import (
	"errors"
	"fmt"
	"math"
)

type runtimeCounter struct {
	Name        string
	Value       float64
	IntervalSec float64
	Increment   bool
}

// decodeRuntimeCounter extracts a .NET System.Runtime/EventCounters sample
// from its nested payload. Increment values are counts, not rates per second.
// Counters outside the supported GC generations return an empty result.
func decodeRuntimeCounter(values map[string]any) (runtimeCounter, error) {
	// EventCounters wraps Payload in an unnamed outer object.
	outer, ok := values[""].(map[string]any)
	if !ok {
		return runtimeCounter{}, errors.New("missing runtime counter outer object")
	}
	payload, ok := outer["Payload"].(map[string]any)
	if !ok {
		return runtimeCounter{}, errors.New("missing runtime counter Payload object")
	}
	name, ok := payload["Name"].(string)
	if !ok || name == "" {
		return runtimeCounter{}, errors.New("invalid runtime counter name")
	}
	if _, ok := gcGeneration(name); !ok {
		return runtimeCounter{}, nil
	}
	// IntervalSec is a NetTrace Single; Mean and Increment are Doubles.
	interval, ok := payload["IntervalSec"].(float32)
	if !ok || interval <= 0 || math.IsNaN(float64(interval)) || math.IsInf(float64(interval), 0) {
		return runtimeCounter{}, fmt.Errorf("invalid runtime counter %q interval", name)
	}
	var field string
	switch payload["CounterType"] {
	case "Mean":
		field = "Mean"
	case "Sum":
		field = "Increment"
	default:
		return runtimeCounter{}, fmt.Errorf("unsupported runtime counter %q type: %v", name, payload["CounterType"])
	}
	value, ok := payload[field].(float64)
	if !ok || math.IsNaN(value) || math.IsInf(value, 0) {
		return runtimeCounter{}, fmt.Errorf("invalid runtime counter %q %s value", name, field)
	}
	return runtimeCounter{
		Name: name, Value: value, IntervalSec: float64(interval), Increment: field == "Increment",
	}, nil
}

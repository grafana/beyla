// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package services // import "go.opentelemetry.io/obi/pkg/appolly/services"

import (
	"fmt"
	"strings"

	"github.com/invopop/jsonschema"
	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/internal/helpers/maps"
)

const (
	// if the corresponding bit is set to 1, this means that this signal
	// is not going to be emitted
	blockMetrics = maps.Bits(1 << iota)
	blockTraces
	blockLogs
)

var modeForText = map[string]maps.Bits{
	"metrics": blockMetrics,
	"traces":  blockTraces,
	"logs":    blockLogs,
}

const (
	// the zero-value of ExportModes (blockSignal == 0) means that the value is unset.
	// This is, all the signals are allowed.
	// In the corresponding YAML is a null or undefined value
	unset = maps.Bits(0)
	// the -1 (all bits to one) value of ExportModes means that the value is set to
	// an empty set: all the signals are blocked.
	// In the corresponding YAML it's an empty sequence []
	blockAll = maps.Bits(^uint(0))
)

// ExportModeUnset corresponds to an undefined export mode in the configuration YAML
// (null or undefined value). This means that all the signals (traces, metrics, logs) are
// going to be exported
var ExportModeUnset = ExportModes{blockSignal: unset}

// ExportModes specifies which signals are going to be exported for a given service,
// via the public methods CanExportTraces, CanExportMetrics, and CanExportLogs.
// Internally, it has three modes of operation depending on how it is defined in the YAML:
//   - When it is undefined or null in the YAML, it will allow exporting all the signals
//     (as no blocking signals are defined)
//   - When it is defined as an empty list in the YAML, it will block all the signals. No
//     signals (metrics, traces, logs) are exported.
//   - When it is defined as a non-empty list, it will only allow the explicitly specified signals.
type ExportModes struct {
	blockSignal maps.Bits
}

func (ExportModes) JSONSchema() *jsonschema.Schema {
	exportModes := make([]any, 0, len(modeForText))

	for k := range modeForText {
		exportModes = append(exportModes, k)
	}
	return &jsonschema.Schema{
		Type: "array",
		Items: &jsonschema.Schema{
			Type: "string",
			Enum: exportModes,
		},
		Description: "List of signals to export. If undefined or null, all signals are exported. If an empty list, no signals are exported.",
	}
}

func NewExportModes() ExportModes {
	return ExportModes{blockSignal: blockAll}
}

// CanExportTraces reports whether traces can be exported.
// It's provided as a convenience function.
func (modes ExportModes) CanExportTraces() bool {
	return !modes.blockSignal.Has(blockTraces)
}

// CanExportMetrics reports whether metrics can be exported.
// It's provided as a convenience function.
func (modes ExportModes) CanExportMetrics() bool {
	return !modes.blockSignal.Has(blockMetrics)
}

// CanExportLogs reports whether logs can be exported.
// It's provided as a convenience function.
func (modes ExportModes) CanExportLogs() bool {
	return !modes.blockSignal.Has(blockLogs)
}

// Allow ExportModes to be pragmatically constructed:
//
//  modes := NewExportModes()
//  modes.AllowMetrics() // export metrics only

func (modes *ExportModes) AllowTraces() {
	modes.blockSignal ^= blockTraces
}

func (modes *ExportModes) AllowMetrics() {
	modes.blockSignal ^= blockMetrics
}

func (modes *ExportModes) AllowLogs() {
	modes.blockSignal ^= blockLogs
}

func (modes *ExportModes) UnmarshalYAML(value *yaml.Node) error {
	// by default, everything is blocked, and we will unblock each signal
	// as long as we parse them in the YAML
	modes.blockSignal = blockAll
	if value.Kind != yaml.SequenceNode {
		return fmt.Errorf("ExportModes: unexpected YAML node kind %d", value.Kind)
	}
	for i, inner := range value.Content {
		if inner.Kind != yaml.ScalarNode {
			return fmt.Errorf("ExportModes[%d]: : unexpected YAML node kind %d", i, inner.Kind)
		}
		if mode, ok := modeForText[inner.Value]; !ok {
			return fmt.Errorf("ExportModes[%d]: unknown export mode %q", i, inner.Value)
		} else {
			// a given signal is defined. Remove it from the blocking list
			modes.blockSignal ^= mode
		}
	}
	return nil
}

// UnmarshalText implements encoding.TextUnmarshaler for ExportModes.
// It parses a comma-separated list of export modes (e.g., "metrics,traces").
// An empty string blocks all signals.
func (modes *ExportModes) UnmarshalText(text []byte) error {
	modes.blockSignal = blockAll
	if len(text) == 0 {
		return nil
	}
	for _, part := range strings.Split(string(text), ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if mode, ok := modeForText[part]; !ok {
			return fmt.Errorf("ExportModes: unknown export mode %q", part)
		} else {
			modes.blockSignal ^= mode
		}
	}
	return nil
}

func (modes ExportModes) MarshalYAML() (any, error) {
	if modes.blockSignal == unset {
		return nil, nil
	}
	node := yaml.Node{
		Kind: yaml.SequenceNode,
	}
	// return an empty sequence, in opposition of "null" in the unset case
	if modes.blockSignal == blockAll {
		return node, nil
	}
	for text, mode := range modeForText {
		// the given signal is not explicitly blocked, so we can list it as allowed
		if !modes.blockSignal.Has(mode) {
			node.Content = append(node.Content, &yaml.Node{
				Kind:  yaml.ScalarNode,
				Value: text,
			})
		}
	}
	return node, nil
}

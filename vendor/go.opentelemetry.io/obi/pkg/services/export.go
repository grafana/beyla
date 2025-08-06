// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package services

import (
	"fmt"

	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/components/helpers/maps"
)

const (
	exportMetrics = maps.Bits(1 << iota)
	exportTraces
)

var modeForText = map[string]maps.Bits{
	"metrics": exportMetrics,
	"traces":  exportTraces,
}

type ExportModes struct {
	items maps.Bits
}

func (modes *ExportModes) canExport(mode maps.Bits) bool {
	if modes == nil {
		return true
	}
	return modes.items.Has(mode)
}

// CanExportTraces reports whether traces can be exported.
// It's provided as a convenience function.
func (modes *ExportModes) CanExportTraces() bool {
	return modes.canExport(exportTraces)
}

// CanExportMetrics reports whether metrics can be exported.
// It's provided as a convenience function.
func (modes *ExportModes) CanExportMetrics() bool {
	return modes.canExport(exportMetrics)
}

func (modes *ExportModes) UnmarshalYAML(value *yaml.Node) error {
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
			modes.items |= mode
		}
	}
	return modes.UnmarshalText([]byte(value.Value))
}

func (modes *ExportModes) UnmarshalText(text []byte) error {
	var options []string
	if err := yaml.Unmarshal(text, &options); err != nil {
		return fmt.Errorf("invalid export_modes: %w", err)
	}
	if options == nil {
		return nil
	}
	modes.items = maps.MappedBits(options, modeForText)
	return nil
}

func (modes *ExportModes) MarshalYAML() (any, error) {
	if modes == nil {
		return nil, nil
	}
	node := yaml.Node{
		Kind: yaml.SequenceNode,
	}
	for text, mode := range modeForText {
		if modes.items.Has(mode) {
			node.Content = append(node.Content, &yaml.Node{
				Kind:  yaml.ScalarNode,
				Value: text,
			})
		}
	}
	return node, nil
}

func (modes *ExportModes) MarshalText() ([]byte, error) {
	var options []string
	if modes != nil {
		options = make([]string, 0, len(modeForText))
		for text, mode := range modeForText {
			if modes.items.Has(mode) {
				options = append(options, text)
			}
		}
	}
	return yaml.Marshal(options)
}

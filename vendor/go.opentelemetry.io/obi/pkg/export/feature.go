// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/internal/helpers/maps"
)

// Features is a bitmask of enabled metric features.
// Each Features value can contain data about a single feature or a combination of OR-ed features.
type Features maps.Bits

const (
	FeatureNetwork Features = 1 << iota
	FeatureNetworkInterZone
	FeatureApplication
	FeatureSpan
	FeatureSpanOTel
	FeatureSpanSizes
	FeatureGraph
	FeatureProcess
	FeatureApplicationHost
	FeatureEBPF
	FeatureAll = Features(^uint(0)) // all bits to 1
)

var featureMapper = map[string]maps.Bits{
	"network":                   maps.Bits(FeatureNetwork),
	"network_inter_zone":        maps.Bits(FeatureNetworkInterZone),
	"application":               maps.Bits(FeatureApplication),
	"application_span":          maps.Bits(FeatureSpan),
	"application_span_otel":     maps.Bits(FeatureSpanOTel),
	"application_span_sizes":    maps.Bits(FeatureSpanSizes),
	"application_service_graph": maps.Bits(FeatureGraph),
	"application_process":       maps.Bits(FeatureProcess),
	"application_host":          maps.Bits(FeatureApplicationHost),
	"ebpf":                      maps.Bits(FeatureEBPF),
	"all":                       maps.Bits(FeatureAll),
	"*":                         maps.Bits(FeatureAll),
}

func LoadFeatures(features []string) Features {
	return Features(maps.MappedBits(features, featureMapper))
}

func (f Features) Has(feature Features) bool {
	return maps.Bits(f).Has(maps.Bits(feature))
}

func (f Features) Any(feature Features) bool {
	return maps.Bits(f).Any(maps.Bits(feature))
}

func (f *Features) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.SequenceNode {
		return fmt.Errorf("feature: unexpected YAML node kind %v", value.Kind)
	}
	features := make([]string, 0, len(value.Content))
	for i, item := range value.Content {
		if item.Kind != yaml.ScalarNode {
			return fmt.Errorf("feature[%d]: unexpected YAML node kind %v (%v)",
				i, item.Kind, item.Value)
		}
		features = append(features, item.Value)
	}
	*f = LoadFeatures(features)
	return nil
}

func (f *Features) UnmarshalText(text []byte) error {
	*f = LoadFeatures(strings.Split(string(text), ","))
	return nil
}

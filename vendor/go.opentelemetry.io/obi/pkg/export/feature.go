// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package export // import "go.opentelemetry.io/obi/pkg/export"

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
	// FeatureEmpty is a special value that can be used to indicate that a feature list has been explicitly
	// set to an empty list (e.g. [] in YAML), as opposed to the undefined value, which would correspond to the
	// zero value.
	FeatureEmpty Features = 1 << iota
	FeatureNetwork
	FeatureNetworkInterZone
	FeatureApplicationRED
	FeatureSpanLegacy
	FeatureSpanOTel
	FeatureSpanSizes
	FeatureGraph
	FeatureApplicationHost
	FeatureEBPF
	FeatureAll = Features(^uint(0)) // all bits to 1
)

// FeatureMapper stays public so any extension package can add and remove feature
// definitions before loading them.
var FeatureMapper = map[string]Features{
	"network":                   FeatureNetwork,
	"network_inter_zone":        FeatureNetworkInterZone,
	"application":               FeatureApplicationRED,
	"application_span":          FeatureSpanLegacy,
	"application_span_otel":     FeatureSpanOTel,
	"application_span_sizes":    FeatureSpanSizes,
	"application_service_graph": FeatureGraph,
	"application_host":          FeatureApplicationHost,
	"ebpf":                      FeatureEBPF,
	"all":                       FeatureAll,
	"*":                         FeatureAll,
}

// AppO11yFeatures is a bitmask of all metrics that are enabled by default for Application RED
// It can be overridden by extension packages
var AppO11yFeatures = FeatureApplicationRED |
	FeatureSpanLegacy |
	FeatureSpanOTel |
	FeatureSpanSizes |
	FeatureGraph |
	FeatureApplicationHost

func LoadFeatures(features []string) Features {
	if len(features) == 0 {
		return FeatureEmpty
	}
	// convert the public data type to the internal representation
	feats := Features(0)
	for _, f := range features {
		feats |= FeatureMapper[f]
	}
	return feats
}

func (f Features) has(feature Features) bool {
	return maps.Bits(f).Has(maps.Bits(feature))
}

func (f Features) any(feature Features) bool {
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

func (f Features) Undefined() bool {
	return f == 0
}

func (f Features) Empty() bool {
	return f == FeatureEmpty
}

func (f Features) AnyAppO11yMetric() bool {
	return f.any(AppO11yFeatures)
}

func (f Features) SpanMetrics() bool {
	return f.any(FeatureSpanLegacy | FeatureSpanOTel)
}

func (f Features) AnySpanMetrics() bool {
	return f.any(FeatureSpanLegacy | FeatureSpanOTel | FeatureSpanSizes)
}

func (f Features) AnyNetwork() bool {
	return f.any(FeatureNetwork | FeatureNetworkInterZone)
}

func (f Features) AppOrSpan() bool {
	return f.any(FeatureApplicationRED |
		FeatureSpanSizes |
		FeatureApplicationHost |
		FeatureSpanLegacy |
		FeatureSpanOTel)
}

func (f Features) LegacySpanMetrics() bool {
	return f.any(FeatureSpanLegacy)
}

func (f Features) ServiceGraph() bool {
	return f.any(FeatureGraph)
}

func (f Features) AppHost() bool {
	return f.any(FeatureApplicationHost)
}

func (f Features) AppRED() bool {
	return f.any(FeatureApplicationRED)
}

func (f Features) SpanSizes() bool {
	return f.any(FeatureSpanSizes)
}

func (f Features) NetworkBytes() bool {
	return f.any(FeatureNetwork)
}

func (f Features) NetworkInterZone() bool {
	return f.any(FeatureNetworkInterZone)
}

func (f Features) BPF() bool {
	return f.any(FeatureEBPF)
}

// InvalidSpanMetricsConfig is used to make sure that you can't define both legacy and OTEL span metrics at the same time
func (f Features) InvalidSpanMetricsConfig() bool {
	return f.has(FeatureSpanLegacy | FeatureSpanOTel)
}

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert // import "go.opentelemetry.io/obi/internal/config/convert"

import (
	"maps"
	"slices"
	"strings"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/obi"
)

const (
	OTLPSpanMetricAttributesPath       = "otel_metrics_export.extra_span_resource_attributes"
	PrometheusSpanMetricAttributesPath = "prometheus_export.extra_span_resource_attributes"
)

type SpanMetricExporterAttributes struct {
	Path       string
	Attributes []attr.Name
}

func ActiveSpanMetricExporterAttributes(cfg *obi.Config) []SpanMetricExporterAttributes {
	var exporters []SpanMetricExporterAttributes
	if cfg.OTELMetrics.EndpointEnabled() {
		names := make([]attr.Name, 0, len(cfg.OTELMetrics.ExtraSpanResourceLabels))
		for _, label := range cfg.OTELMetrics.ExtraSpanResourceLabels {
			names = append(names, attr.Name(label))
		}
		exporters = append(exporters, SpanMetricExporterAttributes{Path: OTLPSpanMetricAttributesPath, Attributes: names})
	}
	if cfg.Prometheus.EndpointEnabled() {
		names := make([]attr.Name, 0, len(cfg.Prometheus.ExtraSpanResourceLabels))
		for _, label := range cfg.Prometheus.ExtraSpanResourceLabels {
			names = append(names, attr.Name(strings.ReplaceAll(label, "_", ".")))
		}
		exporters = append(exporters, SpanMetricExporterAttributes{Path: PrometheusSpanMetricAttributesPath, Attributes: names})
	}
	return exporters
}

// EnabledSpanMetricPairs returns the enabled span metrics grouped as they are reported:
// each group shares one label set.
func EnabledSpanMetricPairs(cfg *obi.Config) [][]attributes.Name {
	features := cfg.JoinMetricsConfig().Features
	var pairs [][]attributes.Name
	if features.SpanMetrics() {
		if features.LegacySpanMetrics() {
			pairs = append(pairs, []attributes.Name{attributes.SpanMetricsLatencyLegacy, attributes.SpanMetricsCallsLegacy})
		} else {
			pairs = append(pairs, []attributes.Name{attributes.SpanMetricsDurationOTel, attributes.SpanMetricsCallsOTel})
		}
	}
	if features.SpanSizes() {
		pairs = append(pairs, []attributes.Name{attributes.SpanMetricsRequestSize, attributes.SpanMetricsResponseSize})
	}
	return pairs
}

func EnabledSpanMetrics(cfg *obi.Config) []attributes.Name {
	var metrics []attributes.Name
	for _, pair := range EnabledSpanMetricPairs(cfg) {
		metrics = append(metrics, pair...)
	}
	return metrics
}

func SameSpanMetricAttributes(a, b []attr.Name) bool {
	return maps.Equal(attrNameSet(a), attrNameSet(b))
}

func attrNameSet(names []attr.Name) map[attr.Name]struct{} {
	set := make(map[attr.Name]struct{}, len(names))
	for _, name := range names {
		set[name] = struct{}{}
	}
	return set
}

func spanMetricSelection(cfg *obi.Config, selection attributes.Selection) attributes.Selection {
	exporters := ActiveSpanMetricExporterAttributes(cfg)
	if len(exporters) == 0 {
		return selection
	}
	extras := exporters[0].Attributes
	extraProm := map[string]struct{}{}
	for _, name := range extras {
		extraProm[name.Prom()] = struct{}{}
	}

	matchable := cloneAttributeSelection(selection)
	matchable.Normalize()

	for _, metric := range EnabledSpanMetrics(cfg) {
		matching := matchable.MatchingV2(metric)
		if len(matching) == 0 && len(extras) == 0 {
			continue
		}
		excluded := map[string]struct{}{}
		for _, il := range matching {
			for _, incl := range il.Include {
				if !attributes.IsGlob(incl) {
					excluded[incl] = struct{}{}
				}
			}
		}
		maps.DeleteFunc(excluded, func(name string, _ struct{}) bool {
			_, isExtra := extraProm[attr.Name(name).Prom()]
			return isExtra
		})

		if selection == nil {
			selection = attributes.Selection{}
		}
		maps.DeleteFunc(selection, func(section attributes.Section, _ attributes.InclusionLists) bool {
			normalized := attributes.Selection{section: {}}
			normalized.Normalize()
			_, sameMetric := normalized[metric.Section]
			return sameMetric
		})
		lists := attributes.InclusionLists{}
		for _, name := range extras {
			lists.Include = append(lists.Include, string(name))
		}
		if len(excluded) > 0 {
			lists.Exclude = slices.Sorted(maps.Keys(excluded))
		}
		selection[metric.Section] = lists
	}
	return selection
}

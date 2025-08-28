// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes

import (
	"maps"
	"path"
	"slices"
	"strings"
	"sync"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// Selection specifies which attributes are allowed for each metric.
// The key is the metric name (either in Prometheus or OpenTelemetry format)
// The value is the enumeration of included/excluded attribute globs
type Selection map[Section]InclusionLists

// selectionMutex is a package-level mutex to protect Selection operations.
var selectionMutex sync.RWMutex

type InclusionLists struct {
	// Include is a list of metric attributes that have to be reported. It can be an attribute
	// name or a wildcard (e.g. k8s.dst.* to include all the attributes starting with k8s.dst).
	// If no include list is provided, the default attribute set will be reported.
	Include []string `yaml:"include"`
	// Exclude will remove attributes from the include list (or the default attribute set).
	// It can be an attribute name or a wildcard.
	Exclude []string `yaml:"exclude"`
}

func asProm(str string) string {
	return strings.ReplaceAll(str, ".", "_")
}

func (i *InclusionLists) includes(name attr.Name) bool {
	for _, incl := range i.Include {
		// to ignore user-input format (dots or underscores) we transform the patterns
		// and the metric names to underscores
		if ok, _ := path.Match(asProm(incl), name.Prom()); ok {
			return true
		}
	}
	return false
}

func (i *InclusionLists) excludes(name attr.Name) bool {
	for _, excl := range i.Exclude {
		// to ignore user-input format (dots or underscores) we transform the patterns
		// and the metric names to underscores
		if ok, _ := path.Match(asProm(excl), name.Prom()); ok {
			return true
		}
	}
	return false
}

// Normalize the user-provided input (error-prone, allowing multiple formats) for unified access
// from the code:
// - Convert underscores (prom-like) to dots (OTEL-like)
// - Remove metric suffixes such as .sum, .total, .bucket, etc...
// - Remove unit suffixes such as .seconds or .bytes
// Only normalize the metric names, as the attribute names are already normalized in the
// PrometheusGetters and OpenTelemetryGetters function
// TODO: validate too
func (incl Selection) Normalize() {
	if incl == nil {
		return
	}

	selectionMutex.Lock()
	defer selectionMutex.Unlock()

	normalized := map[Section]InclusionLists{}
	for metricName, allowedAttrs := range incl {
		normalized[normalizeMetric(metricName)] = allowedAttrs
	}
	// clear the current map before copying again normalized values
	maps.DeleteFunc(incl, func(_ Section, _ InclusionLists) bool { return true })
	maps.Copy(incl, normalized)
}

// Matching returns all the entries of the inclusion list matching the provided metric name.
// This would include "glob-like" entries.
// They are returned from more to less broad scope (for example, for a metric named foo_bar
// it could return the inclusion lists defined with keys "*", "foo_*" and "foo_bar", in that order).
func (incl Selection) Matching(metricName Name) []InclusionLists {
	if incl == nil {
		return nil
	}

	selectionMutex.RLock()
	defer selectionMutex.RUnlock()

	var matchingMetricGlobs []Section
	for glob := range incl {
		if ok, _ := path.Match(string(glob), string(metricName.Section)); ok {
			matchingMetricGlobs = append(matchingMetricGlobs, glob)
		}
	}
	slices.Sort(matchingMetricGlobs)
	inclusionLists := make([]InclusionLists, 0, len(matchingMetricGlobs))
	for _, glob := range matchingMetricGlobs {
		inclusionLists = append(inclusionLists, incl[glob])
	}
	return inclusionLists
}

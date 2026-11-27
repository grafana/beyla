// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes // import "go.opentelemetry.io/obi/pkg/export/attributes"

import (
	"maps"
	"path"
	"slices"
	"strings"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// Selection specifies which attributes are allowed for each signal.
// The key is usually the metric name (either in Prometheus or OpenTelemetry format);
// the key "traces" selects optional attributes for exported OTLP traces.
// The key "resource" selects exported resource attributes.
// The value is the enumeration of included/excluded attribute globs
type Selection map[Section]InclusionLists

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

func (i *InclusionLists) includesExact(name attr.Name) bool {
	for _, incl := range i.Include {
		if asProm(incl) == name.Prom() {
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
	var matching []Section
	for glob := range incl {
		if ok, _ := path.Match(string(glob), string(metricName.Section)); ok {
			matching = append(matching, glob)
		}
	}
	slices.Sort(matching)
	lists := make([]InclusionLists, 0, len(matching))
	for _, glob := range matching {
		lists = append(lists, incl[glob])
	}
	return lists
}

// IsGlob reports whether a metric or attribute selection entry is a pattern rather than an exact name.
func IsGlob(entry string) bool {
	return strings.ContainsAny(entry, "*?[")
}

// MatchingV2 also matches normalized names and applies exact selections after globs.
func (incl Selection) MatchingV2(metricName Name) []InclusionLists {
	globs, exact := incl.MatchingV2Layers(metricName)
	return append(globs, exact...)
}

// MatchingV2Layers returns the inclusion lists of every section matching any of the
// metrics, split into pattern sections and exact sections, each sorted and listed once.
func (incl Selection) MatchingV2Layers(metricNames ...Name) (globs, exact []InclusionLists) {
	if incl == nil {
		return nil, nil
	}

	var matchingMetricGlobs, matchingMetricNames []Section
	for glob := range incl {
		if !slices.ContainsFunc(metricNames, func(metricName Name) bool {
			return matchesMetric(glob, metricName)
		}) {
			continue
		}
		if IsGlob(string(glob)) {
			matchingMetricGlobs = append(matchingMetricGlobs, glob)
		} else {
			matchingMetricNames = append(matchingMetricNames, glob)
		}
	}
	slices.Sort(matchingMetricGlobs)
	slices.Sort(matchingMetricNames)
	for _, glob := range matchingMetricGlobs {
		globs = append(globs, incl[glob])
	}
	for _, name := range matchingMetricNames {
		exact = append(exact, incl[name])
	}
	return globs, exact
}

// matchesMetric also matches the normalized form, because some sections are not
// normalized (e.g. jvm.thread.count).
func matchesMetric(glob Section, metricName Name) bool {
	ok, _ := path.Match(string(glob), string(metricName.Section))
	okNormalized, _ := path.Match(string(glob), string(normalizeMetric(metricName.Section)))
	return ok || okNormalized
}

// RequiresV2Review reports selections whose matching semantics change on migration.
func (incl Selection) RequiresV2Review() bool {
	for section := range getDefinitions(0, nil) {
		name := Name{Section: section}
		if !slices.EqualFunc(incl.Matching(name), incl.MatchingV2(name), func(a, b InclusionLists) bool {
			return slices.Equal(a.Include, b.Include) && slices.Equal(a.Exclude, b.Exclude)
		}) {
			return true
		}
	}
	return false
}

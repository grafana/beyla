package metric

import (
	"maps"
	"path"
	"strings"

	"github.com/grafana/beyla/pkg/internal/export/metric/attr"
)

// Selection specifies which attributes are allowed for each metric.
// The key is the metric name (either in Prometheus or OpenTelemetry format)
// The value is the enumeration of included/excluded attribute globs
type Selection map[Section]InclusionLists

type InclusionLists struct {
	// Include is a list of metrics that need to be reported. It can be an attribute
	// name or a wildcard (e.g. k8s.dst.* to include all the attributes starting with k8s.dst).
	// If no include list is provided, the default attribute set will be reported.
	Include []string `yaml:"include"`
	// Exclude will remove metrics from the include list (or the default attribute set).
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
	normalized := map[Section]InclusionLists{}
	for metricName, allowedAttrs := range incl {
		normalized[normalizeMetric(metricName)] = allowedAttrs
	}
	// clear the current map before copying again normalized values
	maps.DeleteFunc(incl, func(_ Section, _ InclusionLists) bool { return true })
	maps.Copy(incl, normalized)
}

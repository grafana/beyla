package metric

import (
	"path"
	"strings"

	"golang.org/x/exp/maps"

	"github.com/grafana/beyla/pkg/internal/export/metric/attr"
)

// Selection specifies which attributes are allowed for each metric.
// The key is the metric name (either in Prometheus or OpenTelemetry format)
// The value is the enumeration of included/excluded attribute globs
type Selection map[Section]InclusionLists

type InclusionLists struct {
	Include []string `yaml:"include"`
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
	maps.Clear(incl)
	maps.Copy(incl, normalized)
}

package attributes

import (
	"path"
	"strings"

	"golang.org/x/exp/maps"

	"github.com/grafana/beyla/pkg/internal/export/attributes/attr"
)

// Selection specifies which attributes are allowed for each metric.
// The key is the metric name (either in Prometheus or OpenTelemetry format)
// The value is the enumeration of included/excluded attribute globs
type Selection map[attr.Section]InclusionLists

type InclusionLists struct {
	Include []string `yaml:"include"`
	Exclude []string `yaml:"exclude"`
}

func (i *InclusionLists) includes(metricName string) bool {
	for _, incl := range i.Include {
		if ok, _ := path.Match(NormalizeToDot(incl), metricName); ok {
			return true
		}
	}
	return false
}

func (i *InclusionLists) excludes(metricName string) bool {
	for _, excl := range i.Exclude {
		if ok, _ := path.Match(NormalizeToDot(excl), metricName); ok {
			return true
		}
	}
	return false
}

// Normalize the user-provided input (error-prone, allowing multiple formats) for unified access
// from the code:
// - Convert underscores (prom-like) to dots (OTEL-like)
// - Remove metric suffixes such as .sum, .total, .bucket, etc...
// Only normalize the metric names, as the attribute names are already normalized in the
// PrometheusGetters and OpenTelemetryGetters function
// TODO: validate too
func (incl Selection) Normalize() {
	if incl == nil {
		return
	}
	normalized := map[attr.Section]InclusionLists{}
	for metricName, allowedAttrs := range incl {
		normalized[normalizeMetric(metricName)] = allowedAttrs
	}
	maps.Clear(incl)
	maps.Copy(incl, normalized)
}

func normalizeMetric(name attr.Section) attr.Section {
	nameStr := strings.ReplaceAll(string(name), "_", ".")
	for _, suffix := range []string{".bucket", ".sum", ".count", ".total"} {
		if strings.HasSuffix(nameStr, suffix) {
			nameStr = nameStr[:len(nameStr)-len(suffix)]
			break
		}
	}
	return attr.Section(nameStr)
}

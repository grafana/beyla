package attr

import (
	"strings"

	"golang.org/x/exp/maps"

	"github.com/grafana/beyla/pkg/internal/metricname"
)

const globalKey = "global"

// AllowedAttributesDefinition specifies which attributes are allowed for each metric.
// The key is the name of the metric (either in Prometheus or OpenTelemetry format)
// The value is the enumeration of allowed attributes
type AllowedAttributesDefinition map[metricname.Normal][]string

var defaultAllowedAttributes = AllowedAttributesDefinition{
	metricname.NormalBeylaNetworkFlows: []string{
		"k8s.src.owner.name",
		"k8s.src.namespace",
		"k8s.dst.owner.name",
		"k8s.dst.namespace",
		"k8s.cluster.name",
	},
}

// Normalize the user-provided input (error-prone, allowing multiple formats) for unified access
// from the code:
// - Convert underscores (prom-like) to dots (OTEL-like)
// - Remove metric suffixes such as .sum, .total, .bucket, etc...
// Only normalize the metric names, as the attribute names are already normalized in the
// PrometheusGetters and OpenTelemetryGetters function
func (aad AllowedAttributesDefinition) Normalize() {
	if aad == nil {
		return
	}
	normalized := map[metricname.Normal][]string{}
	for metricName, allowedAttrs := range aad {
		normalized[normalizeMetric(metricName)] = allowedAttrs
	}
	maps.Clear(aad)
	maps.Copy(aad, normalized)
}

func normalizeMetric(name metricname.Normal) metricname.Normal {
	nameStr := strings.ReplaceAll(string(name), "_", ".")
	for _, suffix := range []string{".bucket", ".sum", ".count", ".total"} {
		if strings.HasSuffix(nameStr, suffix) {
			nameStr = nameStr[:len(nameStr)-len(suffix)]
			break
		}
	}
	return metricname.Normal(nameStr)
}

// For a given metric name, returns the allowed attributes from the following sources
//   - If the "global" section is provided, returns its defined list of attribute names.
//   - If the metric name section is provided, returns its defined list of attribute names.
//   - If both the "global" and metric name sections are provided, merges both and returns
//     a deduplicated list of attributes.
//   - If none of the above exists, returns the value from the defaultAllowedAttributes, if any.
func (aad AllowedAttributesDefinition) For(metricName metricname.Normal) []string {
	var deduped map[string]struct{}
	if aad != nil {
		deduped = map[string]struct{}{}
		for _, attr := range aad[globalKey] {
			deduped[attr] = struct{}{}
		}
		for _, attr := range aad[metricName] {
			deduped[attr] = struct{}{}
		}
	}
	// if no attributes are defined for a given metric, let's return the default attributes
	if len(deduped) == 0 {
		return defaultAllowedAttributes[metricName]
	}
	allowed := make([]string, 0, len(deduped))
	for attr := range deduped {
		allowed = append(allowed, attr)
	}
	return allowed
}

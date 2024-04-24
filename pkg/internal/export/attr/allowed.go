package attr

import (
	"strings"

	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"
	"golang.org/x/exp/maps"
)

// AllowedAttributesDefinition specifies which attributes are allowed for each metric.
// The key is the name of the metric (either in Prometheus or OpenTelemetry format)
// The value is the enumeration of allowed attributes
type AllowedAttributesDefinition map[Section][]string

var networkKubeAttributes = Definition{
	Attributes: map[string]Default{
		"k8s.src.owner.name": true,
		"k8s.src.namespace":  true,
		"k8s.dst.owner.name": true,
		"k8s.dst.namespace":  true,
		"k8s.cluster.name":   true,
		"k8s.src.name":       false,
		"k8s.src.type":       false,
		"k8s.src.owner.type": false,
		"k8s.src.node.ip":    false,
		"k8s.src.node.name":  false,
		"k8s.dst.name":       false,
		"k8s.dst.type":       false,
		"k8s.dst.owner.type": false,
		"k8s.dst.node.ip":    false,
		"k8s.dst.node.name":  false,
	},
}

var appKubeAttributes = Definition{
	Attributes: map[string]Default{
		"k8s.namespace.name":   false,
		"k8s.pod.name":         false,
		"k8s.deployment.name":  false,
		"k8s.replicaset.name":  false,
		"k8s.daemonset.name":   false,
		"k8s.statefulset.name": false,
		"k8s.node.name":        false,
		"k8s.pod.uid":          false,
		"k8s.pod.start_time":   false,
	},
}

var appCommon = Definition{
	Attributes: map[string]Default{
		string(semconv.ServiceNameKey):    false,
	}
}

var appHTTPDuration = Definition{
	Attributes: map[string]Default{
		string(HTTPRequestMethodKey):      true,
		string(HTTPResponseStatusCodeKey): true,
		string(semconv.HTTPRouteKey):      true,
		string(HTTPUrlPathKey): false,
		string(ClientAddrKey): false,
	},
}

var defaultAllowedAttributes = map[Section]Definition{
	SectionBeylaNetworkFlow: {
		Parents: []*Definition{&networkKubeAttributes},
		Attributes: map[string]Default{
			"beyla.ip":    false,
			"transport":   false,
			"src.address": false,
			"dst.address": false,
			"src.port":    false,
			"dst.port":    false,
			"src.name":    false,
			"dst.name":    false,
			"direction":   false,
			"iface":       false,
		},
	},
	SectionHTTPServerDuration: {
		Parents: []*Definition{&appKubeAttributes, &appHTTPDuration},
	},
	SectionHTTPClientDuration: {
		Parents: []*Definition{&appKubeAttributes, &appHTTPDuration},
	},
	SectionHTTPServerRequestSize: {
		Parents: []*Definition{&appKubeAttributes, &appHTTPDuration},
	},
	SectionHTTPClientRequestSize: {
		Parents: []*Definition{&appKubeAttributes, &appHTTPDuration},
	},
	SectionRPCClientDuration: []string{
		string(semconv.RPCMethodKey),
		string(semconv.RPCSystemKey),
		string(semconv.RPCGRPCStatusCodeKey),
		string(ServerAddrKey),
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
	normalized := map[Section][]string{}
	for metricName, allowedAttrs := range aad {
		normalized[normalizeMetric(metricName)] = allowedAttrs
	}
	maps.Clear(aad)
	maps.Copy(aad, normalized)
}

func normalizeMetric(name Section) Section {
	nameStr := strings.ReplaceAll(string(name), "_", ".")
	for _, suffix := range []string{".bucket", ".sum", ".count", ".total"} {
		if strings.HasSuffix(nameStr, suffix) {
			nameStr = nameStr[:len(nameStr)-len(suffix)]
			break
		}
	}
	return Section(nameStr)
}

// For a given metric name, returns the allowed attributes from the following sources
//   - If the "global" section is provided, returns its defined list of attribute names.
//   - If the metric name section is provided, returns its defined list of attribute names.
//   - If both the "global" and metric name sections are provided, merges both and returns
//     a deduplicated list of attributes.
//   - If none of the above exists, returns the value from the defaultAllowedAttributes, if any.
func (aad AllowedAttributesDefinition) For(metricName Section) []string {
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

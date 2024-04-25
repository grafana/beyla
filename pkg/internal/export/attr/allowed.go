package attr

import (
	"path"
	"slices"
	"strings"

	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"
	"golang.org/x/exp/maps"

	"github.com/grafana/beyla/pkg/internal/helpers"
)

// Selectors specifies which attributes are allowed for each metric.
// The key is the metric name (either in Prometheus or OpenTelemetry format)
// The value is the enumeration of included/excluded attribute globs
type Selectors map[Section]InclusionLists

type InclusionLists struct {
	Include []string `yaml:"include"`
	Exclude []string `yaml:"exclude"`
}

func (i *InclusionLists) include(metricName string) bool {
	for _, incl := range i.Include {
		if ok, _ := path.Match(normalizeToDot(incl), metricName); ok {
			return true
		}
	}
	return false
}

func (i *InclusionLists) exclude(metricName string) bool {
	for _, excl := range i.Exclude {
		if ok, _ := path.Match(normalizeToDot(excl), metricName); ok {
			return true
		}
	}
	return false
}

var networkKubeAttributes = Definition{
	Attributes: map[string]Default{
		K8sSrcOwnerName: true,
		K8sSrcNamespace: true,
		K8sDstOwnerName: true,
		K8sDstNamespace: true,
		K8sClusterName:  true,
		K8sSrcName:      false,
		K8sSrcType:      false,
		K8sSrcOwnerType: false,
		K8sSrcNodeIP:    false,
		K8sSrcNodeName:  false,
		K8sDstName:      false,
		K8sDstType:      false,
		K8sDstOwnerType: false,
		K8sDstNodeIP:    false,
		K8sDstNodeName:  false,
	},
}

var appKubeAttributes = Definition{
	Attributes: map[string]Default{
		K8sNamespaceName:   false,
		K8sPodName:         false,
		K8sDeploymentName:  false,
		K8sReplicaSetName:  false,
		K8sDaemonSetName:   false,
		K8sStatefulSetName: false,
		K8sNodeName:        false,
		K8sPodUID:          false,
		K8sPodStartTime:    false,
	},
}

var appCommon = Definition{
	Attributes: map[string]Default{
		string(semconv.ServiceNameKey): false,
	},
}

var appHTTPDuration = Definition{
	Attributes: map[string]Default{
		string(HTTPRequestMethodKey):      true,
		string(HTTPResponseStatusCodeKey): true,
		string(semconv.HTTPRouteKey):      true,
		string(HTTPUrlPathKey):            false,
		string(ClientAddrKey):             false,
	},
}

var allAttributesList = map[Section]Definition{
	SectionBeylaNetworkFlow: {
		Parents: []*Definition{&networkKubeAttributes},
		Attributes: map[string]Default{
			BeylaIP:    false,
			Transport:  false,
			SrcAddress: false,
			DstAddres:  false,
			SrcPort:    false,
			DstPort:    false,
			SrcName:    false,
			DstName:    false,
			Direction:  false,
			Iface:      false,
		},
	},
	SectionHTTPServerDuration: {
		Parents: []*Definition{&appCommon, &appKubeAttributes, &appHTTPDuration},
	},
	SectionHTTPClientDuration: {
		Parents: []*Definition{&appCommon, &appKubeAttributes, &appHTTPDuration},
	},
	SectionHTTPServerRequestSize: {
		Parents: []*Definition{&appCommon, &appKubeAttributes, &appHTTPDuration},
	},
	SectionHTTPClientRequestSize: {
		Parents: []*Definition{&appCommon, &appKubeAttributes, &appHTTPDuration},
	},
	SectionRPCClientDuration: {
		Parents: []*Definition{&appCommon, &appKubeAttributes},
		Attributes: map[string]Default{
			string(semconv.RPCMethodKey):         true,
			string(semconv.RPCSystemKey):         true,
			string(semconv.RPCGRPCStatusCodeKey): true,
			string(ServerAddrKey):                true,
		},
	},
	SectionRPCServerDuration: {
		Parents: []*Definition{&appCommon, &appKubeAttributes},
		Attributes: map[string]Default{
			string(semconv.RPCMethodKey):         true,
			string(semconv.RPCSystemKey):         true,
			string(semconv.RPCGRPCStatusCodeKey): true,
			//	if span.Type == request.EventTypeGRPC {
			//	attrs = append(attrs, ClientAddr(SpanPeer(span)))
			// } else {
			//	attrs = append(attrs, ServerAddr(SpanPeer(span)))
			// }
			string(ClientAddrKey): true,
		},
	},
}

// Normalize the user-provided input (error-prone, allowing multiple formats) for unified access
// from the code:
// - Convert underscores (prom-like) to dots (OTEL-like)
// - Remove metric suffixes such as .sum, .total, .bucket, etc...
// Only normalize the metric names, as the attribute names are already normalized in the
// PrometheusGetters and OpenTelemetryGetters function
// TODO: validate too
func (incl Selectors) Normalize() {
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

func (incl Selectors) For(metricName Section) []string {
	metricAttributes, ok := allAttributesList[metricName]
	if !ok {
		panic("BUG! metric not found " + metricName)
	}
	inclusionLists, ok := incl[metricName]
	if !ok {
		attrs := helpers.SetToSlice(metricAttributes.Default())
		slices.Sort(attrs)
		return attrs
	}
	addAttributes := map[string]struct{}{}
	for attr := range metricAttributes.All() {
		attr = normalizeToDot(attr)
		if inclusionLists.include(attr) {
			addAttributes[attr] = struct{}{}
		}
	}
	maps.DeleteFunc(addAttributes, func(attr string, _ struct{}) bool {
		return inclusionLists.exclude(normalizeToDot(attr))
	})
	attrs := helpers.SetToSlice(addAttributes)
	slices.Sort(attrs)
	return attrs
}

package attr

import (
	"strings"

	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"
)

type Name attribute.Key

func (an Name) OTEL() attribute.Key {
	return attribute.Key(an)
}

func (an Name) Prom() string {
	return strings.ReplaceAll(string(an), ".", "_")
}

// OpenTelemetry 1.23 semantic convention
const (
	ServiceName               = Name(semconv.ServiceNameKey)
	HTTPRequestMethodKey      = Name("http.request.method")
	HTTPResponseStatusCodeKey = Name("http.response.status_code")
	HTTPUrlPathKey            = Name("url.path")
	HTTPUrlFullKey            = Name("url.full")
	ClientAddrKey             = Name("client.address")
	ServerAddrKey             = Name("server.address")
	ServerPortKey             = Name("server.port")
	HTTPRequestBodySizeKey    = Name("http.request.body.size")
	HTTPResponseBodySizeKey   = Name("http.response.body.size")
	SpanKindKey               = Name("span.kind")
	SpanNameKey               = Name("span.name")
	StatusCodeKey             = Name("status.code")
	SourceKey                 = Name("source")
	ServiceKey                = Name("service")
	ClientKey                 = Name("client")
	ClientNamespaceKey        = Name("client_service_namespace")
	ServerKey                 = Name("server")
	ServerNamespaceKey        = Name("server_service_namespace")
	ConnectionTypeKey         = Name("connection_type")
	DBOperationKey            = Name("db_operation")
	RPCMethod                 = Name(semconv.RPCMethodKey)
	RPCSystem                 = Name(semconv.RPCSystemKey)
	RPCGRPCStatusCode         = Name(semconv.RPCGRPCStatusCodeKey)
	HTTPRoute                 = Name(semconv.HTTPRouteKey)

	K8sNamespaceName   = Name("k8s.namespace.name")
	K8sPodName         = Name("k8s.pod.name")
	K8sDeploymentName  = Name("k8s.deployment.name")
	K8sReplicaSetName  = Name("k8s.replicaset.name")
	K8sDaemonSetName   = Name("k8s.daemonset.name")
	K8sStatefulSetName = Name("k8s.statefulset.name")
	K8sNodeName        = Name("k8s.node.name")
	K8sPodUID          = Name("k8s.pod.uid")
	K8sPodStartTime    = Name("k8s.pod.start_time")
)

// Beyla-specific network attributes
var (
	BeylaIP    = Name("beyla.ip")
	Transport  = Name("transport")
	SrcAddress = Name("src.address")
	DstAddres  = Name("dst.address")
	SrcPort    = Name("src.port")
	DstPort    = Name("dst.port")
	SrcName    = Name("src.name")
	DstName    = Name("dst.name")
	Direction  = Name("direction")
	Iface      = Name("iface")

	K8sSrcOwnerName = Name("k8s.src.owner.name")
	K8sSrcNamespace = Name("k8s.src.namespace")
	K8sDstOwnerName = Name("k8s.dst.owner.name")
	K8sDstNamespace = Name("k8s.dst.namespace")
	K8sClusterName  = Name("k8s.cluster.name")
	K8sSrcName      = Name("k8s.src.name")
	K8sSrcType      = Name("k8s.src.type")
	K8sSrcOwnerType = Name("k8s.src.owner.type")
	K8sSrcNodeIP    = Name("k8s.src.node.ip")
	K8sSrcNodeName  = Name("k8s.src.node.name")
	K8sDstName      = Name("k8s.dst.name")
	K8sDstType      = Name("k8s.dst.type")
	K8sDstOwnerType = Name("k8s.dst.owner.type")
	K8sDstNodeIP    = Name("k8s.dst.node.ip")
	K8sDstNodeName  = Name("k8s.dst.node.name")
)

// other beyla-specific attributes
var (
	// TargetInstanceKey is a Prometheus-only attribute.
	// It will expose the process hostname-pid (or K8s Pod).
	// It is advised for users that to use relabeling rules to
	// override the "instance" attribute with "target" in the
	// Prometheus server. This would be similar to the "multi target pattern":
	// https://prometheus.io/docs/guides/multi-target-exporter/
	TargetInstanceKey = Name("target_instance")
)

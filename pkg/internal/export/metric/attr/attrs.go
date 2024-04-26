package attr

import (
	"go.opentelemetry.io/otel/attribute"
)

// OpenTelemetry 1.23 semantic convention
const (
	HTTPRequestMethodKey      = attribute.Key("http.request.method")
	HTTPResponseStatusCodeKey = attribute.Key("http.response.status_code")
	HTTPUrlPathKey            = attribute.Key("url.path")
	HTTPUrlFullKey            = attribute.Key("url.full")
	ClientAddrKey             = attribute.Key("client.address")
	ServerAddrKey             = attribute.Key("server.address")
	ServerPortKey             = attribute.Key("server.port")
	HTTPRequestBodySizeKey    = attribute.Key("http.request.body.size")
	HTTPResponseBodySizeKey   = attribute.Key("http.response.body.size")
	SpanKindKey               = attribute.Key("span.kind")
	SpanNameKey               = attribute.Key("span.name")
	StatusCodeKey             = attribute.Key("status.code")
	SourceKey                 = attribute.Key("source")
	ServiceKey                = attribute.Key("service")
	ClientKey                 = attribute.Key("client")
	ClientNamespaceKey        = attribute.Key("client_service_namespace")
	ServerKey                 = attribute.Key("server")
	ServerNamespaceKey        = attribute.Key("server_service_namespace")
	ConnectionTypeKey         = attribute.Key("connection_type")
	DBOperationKey            = attribute.Key("db_operation")

	K8sNamespaceName   = "k8s.namespace.name"
	K8sPodName         = "k8s.pod.name"
	K8sDeploymentName  = "k8s.deployment.name"
	K8sReplicaSetName  = "k8s.replicaset.name"
	K8sDaemonSetName   = "k8s.daemonset.name"
	K8sStatefulSetName = "k8s.statefulset.name"
	K8sNodeName        = "k8s.node.name"
	K8sPodUID          = "k8s.pod.uid"
	K8sPodStartTime    = "k8s.pod.start_time"
)

// Beyla-specific network attributes
const (
	BeylaIP    = "beyla.ip"
	Transport  = "transport"
	SrcAddress = "src.address"
	DstAddres  = "dst.address"
	SrcPort    = "src.port"
	DstPort    = "dst.port"
	SrcName    = "src.name"
	DstName    = "dst.name"
	Direction  = "direction"
	Iface      = "iface"

	K8sSrcOwnerName = "k8s.src.owner.name"
	K8sSrcNamespace = "k8s.src.namespace"
	K8sDstOwnerName = "k8s.dst.owner.name"
	K8sDstNamespace = "k8s.dst.namespace"
	K8sClusterName  = "k8s.cluster.name"
	K8sSrcName      = "k8s.src.name"
	K8sSrcType      = "k8s.src.type"
	K8sSrcOwnerType = "k8s.src.owner.type"
	K8sSrcNodeIP    = "k8s.src.node.ip"
	K8sSrcNodeName  = "k8s.src.node.name"
	K8sDstName      = "k8s.dst.name"
	K8sDstType      = "k8s.dst.type"
	K8sDstOwnerType = "k8s.dst.owner.type"
	K8sDstNodeIP    = "k8s.dst.node.ip"
	K8sDstNodeName  = "k8s.dst.node.name"
)

// other beyla-specific attributes
const (
	// TargetInstanceKey is a Prometheus-only attribute.
	// It will expose the process hostname-pid (or K8s Pod).
	// It is advised for users that to use relabeling rules to
	// override the "instance" attribute with "target" in the
	// Prometheus server. This would be similar to the "multi target pattern":
	// https://prometheus.io/docs/guides/multi-target-exporter/
	TargetInstanceKey = "target_instance"
)

// Package attr contains definition of the attribute names of for the metrics, especially
// for the metrics whose reported attributes are selected in the attributes.select YAML option
package attr

import (
	"strings"

	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"
	semconv2 "go.opentelemetry.io/otel/semconv/v1.25.0"
)

// Name of an attribute. This is the common internal representation of a metric attribute name,
// which can be converted to OTEL or Prometheus format right before exporting them.
type Name attribute.Key

func (an Name) OTEL() attribute.Key {
	return attribute.Key(an)
}

func (an Name) Prom() string {
	return strings.ReplaceAll(string(an), ".", "_")
}

// OpenTelemetry 1.23 semantic convention
const (
	HTTPRequestMethod      = Name("http.request.method")
	HTTPResponseStatusCode = Name("http.response.status_code")
	HTTPUrlPath            = Name("url.path")
	HTTPUrlFull            = Name("url.full")
	ClientAddr             = Name("client.address")
	ServerAddr             = Name("server.address")
	ServerPort             = Name("server.port")
	HTTPRequestBodySize    = Name("http.request.body.size")
	SpanKind               = Name("span.kind")
	SpanName               = Name("span.name")
	StatusCode             = Name("status.code")
	Source                 = Name("source")
	Service                = Name("service")
	Client                 = Name("client")
	ClientNamespace        = Name("client_service_namespace")
	Server                 = Name("server")
	ServerNamespace        = Name("server_service_namespace")
	ConnectionType         = Name("connection_type")
	DBOperation            = Name("db.operation.name")
	DBCollectionName       = Name("db.collection.name")
	DBSystem               = Name(semconv.DBSystemKey)
	ErrorType              = Name("error.type")
	RPCMethod              = Name(semconv.RPCMethodKey)
	RPCSystem              = Name(semconv.RPCSystemKey)
	RPCGRPCStatusCode      = Name(semconv.RPCGRPCStatusCodeKey)
	HTTPRoute              = Name(semconv.HTTPRouteKey)
	MessagingOpType        = Name("messaging.operation.type")
	MessagingSystem        = Name(semconv.MessagingSystemKey)
	MessagingDestination   = Name(semconv.MessagingDestinationNameKey)

	K8sNamespaceName    = Name("k8s.namespace.name")
	K8sPodName          = Name("k8s.pod.name")
	K8sDeploymentName   = Name("k8s.deployment.name")
	K8sReplicaSetName   = Name("k8s.replicaset.name")
	K8sDaemonSetName    = Name("k8s.daemonset.name")
	K8sStatefulSetName  = Name("k8s.statefulset.name")
	K8sUnknownOwnerName = Name("k8s.owner.name")
	K8sNodeName         = Name("k8s.node.name")
	K8sPodUID           = Name("k8s.pod.uid")
	K8sPodStartTime     = Name("k8s.pod.start_time")
)

// Beyla-specific network attributes
const (
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
	SrcCIDR    = Name("src.cidr")
	DstCIDR    = Name("dst.cidr")

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

// Process Metrics following OTEL 1.26 experimental conventions
// https://opentelemetry.io/docs/specs/semconv/resource/process/
// https://opentelemetry.io/docs/specs/semconv/system/process-metrics/

const (
	ProcCommand     = Name(semconv.ProcessCommandKey)
	ProcCommandLine = Name(semconv.ProcessCommandLineKey)
	ProcCPUState    = Name("process.cpu.state")
	ProcDiskIODir   = Name(semconv2.DiskIoDirectionKey)
	ProcNetIODir    = Name(semconv2.NetworkIoDirectionKey)
	ProcOwner       = Name(semconv.ProcessOwnerKey)
	ProcParentPid   = Name(semconv.ProcessParentPIDKey)
	ProcPid         = Name(semconv.ProcessPIDKey)
	ProcCommandArgs = Name(semconv.ProcessCommandArgsKey)
	ProcExecName    = Name(semconv.ProcessExecutableNameKey)
	ProcExecPath    = Name(semconv.ProcessExecutablePathKey)
)

// other beyla-specific attributes
const (
	// TargetInstance is a Prometheus-only attribute.
	// It will expose the process hostname-pid (or K8s Pod).
	// It is advised for users that to use relabeling rules to
	// override the "instance" attribute with "target" in the
	// Prometheus server. This would be similar to the "multi target pattern":
	// https://prometheus.io/docs/guides/multi-target-exporter/
	TargetInstance = Name("target.instance")

	// ServiceName and ServiceNamespace are going to be used only on Prometheus
	// as metric attributes. The OTEL exporter already uses them as Resource
	// attributes, which can't be enabled/disabled by the users
	ServiceName      = Name(semconv.ServiceNameKey)
	ServiceNamespace = Name(semconv.ServiceNamespaceKey)

	HostName = Name(semconv.HostNameKey)
)

// traces related attributes
var (
	// SQL
	DBQueryText = Name("db.query.text")
)

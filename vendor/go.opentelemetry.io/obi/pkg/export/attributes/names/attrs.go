// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package attr contains definition of the attribute names of for the metrics, especially
// for the metrics whose reported attributes are selected in the attributes.select YAML option
package attr

import (
	"strings"

	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"
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
	HTTPResponseBodySize   = Name("http.response.body.size")
	SpanKind               = Name("span.kind")
	SpanName               = Name("span.name")
	StatusCode             = Name("status.code")
	Source                 = Name("source")
	Client                 = Name("client")
	ClientNamespace        = Name("client_service_namespace")
	Server                 = Name("server")
	ServerNamespace        = Name("server_service_namespace")
	ConnectionType         = Name("connection_type")
	DBOperation            = Name("db.operation.name")
	DBCollectionName       = Name("db.collection.name")
	DBSystemName           = Name("db.system.name")
	ErrorType              = Name("error.type")
	RPCMethod              = Name(semconv.RPCMethodKey)
	RPCSystem              = Name(semconv.RPCSystemKey)
	RPCService             = Name(semconv.RPCServiceKey)
	RPCGRPCStatusCode      = Name(semconv.RPCGRPCStatusCodeKey)
	HTTPRoute              = Name(semconv.HTTPRouteKey)
	MessagingOpName        = Name("messaging.operation.name")
	MessagingOpType        = Name("messaging.operation.type")
	MessagingMessageID     = Name(semconv.MessagingMessageIDKey)
	MessagingSystem        = Name(semconv.MessagingSystemKey)
	MessagingDestination   = Name(semconv.MessagingDestinationNameKey)
	GraphQLDocument        = Name(semconv.GraphqlDocumentKey)
	GraphQLOperationName   = Name(semconv.GraphqlOperationNameKey)
	GraphQLOperationType   = Name(semconv.GraphqlOperationTypeKey)
	DNSAnswers             = Name("dns.answers")
	ErrorMessage           = Name("error.message")
	TelemetrySDKLanguage   = Name(semconv.TelemetrySDKLanguageKey)

	K8sNamespaceName   = Name("k8s.namespace.name")
	K8sPodName         = Name("k8s.pod.name")
	K8sContainerName   = Name("k8s.container.name")
	K8sDeploymentName  = Name("k8s.deployment.name")
	K8sReplicaSetName  = Name("k8s.replicaset.name")
	K8sJobName         = Name("k8s.job.name")
	K8sCronJobName     = Name("k8s.cronjob.name")
	K8sDaemonSetName   = Name("k8s.daemonset.name")
	K8sStatefulSetName = Name("k8s.statefulset.name")
	K8sOwnerName       = Name("k8s.owner.name")
	K8sNodeName        = Name("k8s.node.name")
	K8sPodUID          = Name("k8s.pod.uid")
	K8sPodStartTime    = Name("k8s.pod.start_time")
	K8sKind            = Name("k8s.kind")
)

// OBI-specific network attributes
// obi.-prefixed attributes are a var instead of a constant to allow overriding the prefix
// from components that vendor OBI as a library

// VendorPrefix allows identifying some metrics (network, internal counters...)
// as custom metrics, since at the moment they don't follow any semantic convention for them.
// This value can be overridden when OBI is vendored as a library (e.g. from the OTEL collector)
var (
	VendorPrefix  = "obi"
	VendorSDKName = "opentelemetry-ebpf-instrumentation"
)

var OBIIP = Name("obi.ip")

const (
	Transport   = Name("transport")
	NetworkType = Name("network.type")
	SrcAddress  = Name("src.address")
	DstAddres   = Name("dst.address")
	SrcPort     = Name("src.port")
	DstPort     = Name("dst.port")
	SrcName     = Name("src.name")
	DstName     = Name("dst.name")
	Iface       = Name("iface")
	SrcCIDR     = Name("src.cidr")
	DstCIDR     = Name("dst.cidr")
	SrcZone     = Name("src.zone")
	DstZone     = Name("dst.zone")

	ClientPort = Name("client.port")

	// Direction values: request or response
	Direction = Name("direction")
	// IfaceDirection values: ingress or egress
	IfaceDirection = Name("iface.direction")

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

// other OBI-specific attributes
const (
	// Instance and Job are only explicitly used in the Prometheus
	// exporter, as the OpenTelemetry SDK already sets them implicitly.
	// It is advised for users to configure their Prometheus scraper with
	// the `honor_labels` option set to true, to avoid overwriting the
	// instance attribute with the target attribute.
	Instance = Name("instance")
	Job      = Name("job")

	// ServiceName and ServiceNamespace are going to be used only on Prometheus
	// as metric attributes. The OTEL exporter already uses them as Resource
	// attributes, which can't be enabled/disabled by the users
	ServiceName      = Name(semconv.ServiceNameKey)
	ServiceNamespace = Name(semconv.ServiceNamespaceKey)

	HostName = Name(semconv.HostNameKey)
	HostID   = Name(semconv.HostIDKey)

	ServiceInstanceID = Name(semconv.ServiceInstanceIDKey)
	SkipSpanMetrics   = Name("span.metrics.skip")

	VendorVersionSuffix  = Name(".version")
	VendorRevisionSuffix = Name(".revision")
)

// traces related attributes
const (
	// SQL
	DBQueryText          = Name("db.query.text")
	DBResponseStatusCode = Name("db.response.status_code")
	DBNamespace          = Name("db.namespace")

	// Messaging
	MessagingPartition   = Name("messaging.destination.partition.id")
	MessagingKafkaOffset = Name("messaging.kafka.offset")

	// Elasticsearch
	ElasticsearchNodeName = Name("elasticsearch.node.name")

	// AWS
	AWSRequestID         = Name("aws.request_id")
	AWSExtendedRequestID = Name("aws.extended_request_id")
	AWSS3Bucket          = Name("aws.s3.bucket")
	AWSS3Key             = Name("aws.s3.key")
	AWSSQSQueueURL       = Name("aws.sqs.queue_url")

	// Cloud
	CloudRegion = Name(semconv.CloudRegionKey)
)

// Beyla specific GPU events
const (
	// GPU/Cuda related attributes
	CudaKernelName = Name("cuda.kernel.name")
	CudaMemcpyKind = Name("cuda.memcpy.kind")
)

// DNS events
const (
	DNSQuestionName = Name("dns.question.name")
)

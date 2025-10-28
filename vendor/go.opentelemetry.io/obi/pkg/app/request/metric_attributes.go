// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"strings"

	"go.opentelemetry.io/otel/attribute"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func HTTPRequestMethod(val string) attribute.KeyValue {
	return attribute.Key(attr.HTTPRequestMethod).String(val)
}

func HTTPResponseStatusCode(val int) attribute.KeyValue {
	return attribute.Key(attr.HTTPResponseStatusCode).Int(val)
}

func HTTPResponseBodySize(val int64) attribute.KeyValue {
	return attribute.Key(attr.HTTPResponseBodySize).Int64(val)
}

func HTTPUrlPath(val string) attribute.KeyValue {
	return attribute.Key(attr.HTTPUrlPath).String(val)
}

func HTTPUrlFull(val string) attribute.KeyValue {
	return attribute.Key(attr.HTTPUrlFull).String(val)
}

func ClientAddr(val string) attribute.KeyValue {
	return attribute.Key(attr.ClientAddr).String(val)
}

func ServerAddr(val string) attribute.KeyValue {
	return attribute.Key(attr.ServerAddr).String(val)
}

func ServerPort(val int) attribute.KeyValue {
	return attribute.Key(attr.ServerPort).Int(val)
}

func HTTPRequestBodySize(val int) attribute.KeyValue {
	return attribute.Key(attr.HTTPRequestBodySize).Int(val)
}

func SpanKindMetric(val string) attribute.KeyValue {
	return attribute.Key(attr.SpanKind).String(val)
}

func SpanNameMetric(val string) attribute.KeyValue {
	return attribute.Key(attr.SpanName).String(val)
}

func SourceMetric(val string) attribute.KeyValue {
	return attribute.Key(attr.Source).String(val)
}

func StatusCodeMetric(val string) attribute.KeyValue {
	return attribute.Key(attr.StatusCode).String(val)
}

func ClientMetric(val string) attribute.KeyValue {
	return attribute.Key(attr.Client).String(val)
}

func ClientNamespaceMetric(val string) attribute.KeyValue {
	return attribute.Key(attr.ClientNamespace).String(val)
}

func ServerMetric(val string) attribute.KeyValue {
	return attribute.Key(attr.Server).String(val)
}

func ServerNamespaceMetric(val string) attribute.KeyValue {
	return attribute.Key(attr.ServerNamespace).String(val)
}

func DBQueryText(val string) attribute.KeyValue {
	return attribute.Key(attr.DBQueryText).String(val)
}

func DBNamespace(val string) attribute.KeyValue {
	return attribute.Key(attr.DBNamespace).String(val)
}

func DBResponseStatusCode(val string) attribute.KeyValue {
	return attribute.Key(attr.DBResponseStatusCode).String(val)
}

func MessagingPartition(val int) attribute.KeyValue {
	return attribute.Key(attr.MessagingPartition).Int(val)
}

func MessagingKafkaOffset(val int64) attribute.KeyValue {
	return attribute.Key(attr.MessagingKafkaOffset).Int64(val)
}

func DBCollectionName(val string) attribute.KeyValue {
	return attribute.Key(attr.DBCollectionName).String(val)
}

func DBOperationName(val string) attribute.KeyValue {
	return attribute.Key(attr.DBOperation).String(val)
}

func DBSystemName(val string) attribute.KeyValue {
	// TODO: replace by semconv.DBSystemName when we update to OTEL semconv library 1.30
	return attribute.Key(attr.DBSystemName).String(val)
}

func GraphqlOperationType(val string) attribute.KeyValue {
	// TODO: replace once it's available in semconv
	return attribute.Key(attr.GraphQLOperationType).String(val)
}

func ElasticsearchNodeName(val string) attribute.KeyValue {
	// TODO: replace it when it's available in the imported semconv version
	return attribute.Key(attr.ElasticsearchNodeName).String(val)
}

func ErrorType(val string) attribute.KeyValue {
	return attribute.Key(attr.ErrorType).String(val)
}

func MessagingOperationType(val string) attribute.KeyValue {
	return attribute.Key(attr.MessagingOpType).String(val)
}

func RPCSystem(val string) attribute.KeyValue {
	return attribute.Key(attr.RPCSystem).String(val)
}

func RPCMethod(val string) attribute.KeyValue {
	return attribute.Key(attr.RPCMethod).String(val)
}

func AWSRequestID(val string) attribute.KeyValue {
	return attribute.Key(attr.AWSRequestID).String(val)
}

func AWSExtendedRequestID(val string) attribute.KeyValue {
	return attribute.Key(attr.AWSExtendedRequestID).String(val)
}

func AWSS3Bucket(val string) attribute.KeyValue {
	return attribute.Key(attr.AWSS3Bucket).String(val)
}

func AWSS3Key(val string) attribute.KeyValue {
	return attribute.Key(attr.AWSS3Key).String(val)
}

func CloudRegion(val string) attribute.KeyValue {
	return attribute.Key(attr.CloudRegion).String(val)
}

func SpanHost(span *Span) string {
	if span.HostName != "" {
		return span.HostName
	}

	return span.Host
}

func SpanPeer(span *Span) string {
	if span.PeerName != "" {
		return span.PeerName
	}

	return span.Peer
}

func HostFromSchemeHost(span *Span) string {
	if strings.Index(span.Statement, SchemeHostSeparator) > 0 {
		schemeHost := strings.Split(span.Statement, SchemeHostSeparator)
		if schemeHost[1] != "" {
			return schemeHost[1]
		}
	}

	return ""
}

func HTTPClientHost(span *Span) string {
	if host := HostFromSchemeHost(span); host != "" {
		return host
	}

	return HostAsServer(span)
}

func HTTPScheme(span *Span) string {
	if strings.Index(span.Statement, SchemeHostSeparator) > 0 {
		schemeHost := strings.Split(span.Statement, SchemeHostSeparator)
		return schemeHost[0]
	}

	return ""
}

func URLFull(scheme, host, path string) string {
	url := path
	if len(host) > 0 {
		url = host + url
		if len(scheme) > 0 {
			url = scheme + "://" + url
		}
	}

	return url
}

func HostAsServer(span *Span) string {
	if span.OtherNamespace != "" && span.OtherNamespace != span.Service.UID.Namespace && span.HostName != "" {
		if span.IsClientSpan() {
			return SpanHost(span) + "." + span.OtherNamespace
		}
	}

	return SpanHost(span)
}

func PeerAsClient(span *Span) string {
	if span.OtherNamespace != "" && span.OtherNamespace != span.Service.UID.Namespace && span.PeerName != "" {
		if !span.IsClientSpan() {
			return SpanPeer(span) + "." + span.OtherNamespace
		}
	}

	return SpanPeer(span)
}

func CudaKernel(val string) attribute.KeyValue {
	return attribute.Key(attr.CudaKernelName).String(val)
}

// These are defined here https://docs.nvidia.com/cuda/cuda-runtime-api/group__CUDART__TYPES.html#group__CUDART__TYPES_1gg18fa99055ee694244a270e4d5101e95bdeec295de8a74ac2a74f98ffb6c5d7c7
// in the enum cudaMemcpyKind
const (
	MemcpyHostToHost     = 0
	MemcpyHostToDevice   = 1
	MemcpyDeviceToHost   = 2
	MemcpyDeviceToDevice = 3
)

func CudaMemcpyName(val int) string {
	switch val {
	case MemcpyHostToHost:
		return "MemcpyHostToHost"
	case MemcpyHostToDevice:
		return "MemcpyHostToDevice"
	case MemcpyDeviceToHost:
		return "MemcpyDeviceToHost"
	case MemcpyDeviceToDevice:
		return "MemcpyDeviceToDevice"
	default:
		return "MemcpyDefault"
	}
}

func CudaMemcpy(val int) attribute.KeyValue {
	return attribute.Key(attr.CudaMemcpyKind).String(CudaMemcpyName(val))
}

func Job(val string) attribute.KeyValue {
	return attribute.Key(attr.MessagingOpType).String(val)
}

func Instance(val string) attribute.KeyValue {
	return attribute.Key(attr.MessagingOpType).String(val)
}

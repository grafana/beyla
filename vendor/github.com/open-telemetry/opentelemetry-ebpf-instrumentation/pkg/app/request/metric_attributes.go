package request

import (
	"strings"

	"go.opentelemetry.io/otel/attribute"

	attr "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes/names"
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

func ConnectionTypeMetric(val string) attribute.KeyValue {
	return attribute.Key(attr.ConnectionType).String(val)
}

func DBQueryText(val string) attribute.KeyValue {
	return attribute.Key(attr.DBQueryText).String(val)
}

func DBResponseStatusCode(val string) attribute.KeyValue {
	return attribute.Key(attr.DBResponseStatusCode).String(val)
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

func ErrorType(val string) attribute.KeyValue {
	return attribute.Key(attr.ErrorType).String(val)
}

func MessagingOperationType(val string) attribute.KeyValue {
	return attribute.Key(attr.MessagingOpType).String(val)
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

func HTTPClientHost(span *Span) string {
	if strings.Index(span.Statement, SchemeHostSeparator) > 0 {
		schemeHost := strings.Split(span.Statement, SchemeHostSeparator)
		if schemeHost[1] != "" {
			return schemeHost[1]
		}
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

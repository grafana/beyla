package metric

import (
	"go.opentelemetry.io/otel/attribute"

	"github.com/grafana/beyla/pkg/internal/export/metric/attr"
	"github.com/grafana/beyla/pkg/internal/request"
)

func HTTPRequestMethod(val string) attribute.KeyValue {
	return attr.HTTPRequestMethodKey.String(val)
}

func HTTPResponseStatusCode(val int) attribute.KeyValue {
	return attr.HTTPResponseStatusCodeKey.Int(val)
}

func HTTPUrlPath(val string) attribute.KeyValue {
	return attr.HTTPUrlPathKey.String(val)
}

func HTTPUrlFull(val string) attribute.KeyValue {
	return attr.HTTPUrlFullKey.String(val)
}

func ClientAddr(val string) attribute.KeyValue {
	return attr.ClientAddrKey.String(val)
}

func ServerAddr(val string) attribute.KeyValue {
	return attr.ServerAddrKey.String(val)
}

func ServerPort(val int) attribute.KeyValue {
	return attr.ServerPortKey.Int(val)
}

func HTTPRequestBodySize(val int) attribute.KeyValue {
	return attr.HTTPRequestBodySizeKey.Int(val)
}

func HTTPResponseBodySize(val int) attribute.KeyValue {
	return attr.HTTPResponseBodySizeKey.Int(val)
}

func SpanKindMetric(val string) attribute.KeyValue {
	return attr.SpanKindKey.String(val)
}

func SpanNameMetric(val string) attribute.KeyValue {
	return attr.SpanNameKey.String(val)
}

func SourceMetric(val string) attribute.KeyValue {
	return attr.SourceKey.String(val)
}

func ServiceMetric(val string) attribute.KeyValue {
	return attr.ServiceKey.String(val)
}

func StatusCodeMetric(val int) attribute.KeyValue {
	return attr.StatusCodeKey.Int(val)
}

func ClientMetric(val string) attribute.KeyValue {
	return attr.ClientKey.String(val)
}

func ClientNamespaceMetric(val string) attribute.KeyValue {
	return attr.ClientNamespaceKey.String(val)
}

func ServerMetric(val string) attribute.KeyValue {
	return attr.ServerKey.String(val)
}

func ServerNamespaceMetric(val string) attribute.KeyValue {
	return attr.ServerNamespaceKey.String(val)
}

func ConnectionTypeMetric(val string) attribute.KeyValue {
	return attr.ConnectionTypeKey.String(val)
}

func SpanHost(span *request.Span) string {
	if span.HostName != "" {
		return span.HostName
	}

	return span.Host
}

func SpanPeer(span *request.Span) string {
	if span.PeerName != "" {
		return span.PeerName
	}

	return span.Peer
}

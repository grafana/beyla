package request

import (
	"go.opentelemetry.io/otel/attribute"

	attr "github.com/grafana/beyla/pkg/internal/export/attributes/names"
)

func HTTPRequestMethod(val string) attribute.KeyValue {
	return attribute.Key(attr.HTTPRequestMethod).String(val)
}

func HTTPResponseStatusCode(val int) attribute.KeyValue {
	return attribute.Key(attr.HTTPResponseStatusCode).Int(val)
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

func ServiceMetric(val string) attribute.KeyValue {
	return attribute.Key(attr.Service).String(val)
}

func StatusCodeMetric(val int) attribute.KeyValue {
	return attribute.Key(attr.StatusCode).Int(val)
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

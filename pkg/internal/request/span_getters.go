package request

import (
	"strconv"

	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"

	"github.com/grafana/beyla/pkg/internal/export/metric"
	"github.com/grafana/beyla/pkg/internal/export/metric/attr"
)

// SpanOTELGetters returns the metric.Getter function that returns the
// OTEL attribute.KeyValue of a given attribute name.
func SpanOTELGetters(name attr.Name) (metric.Getter[*Span, attribute.KeyValue], bool) {
	var getter metric.Getter[*Span, attribute.KeyValue]
	switch name {
	case attr.HTTPRequestMethod:
		getter = func(s *Span) attribute.KeyValue { return HTTPRequestMethod(s.Method) }
	case attr.HTTPResponseStatusCode:
		getter = func(s *Span) attribute.KeyValue { return HTTPResponseStatusCode(s.Status) }
	case attr.HTTPRoute:
		getter = func(s *Span) attribute.KeyValue { return semconv.HTTPRoute(s.Route) }
	case attr.HTTPUrlPath:
		getter = func(s *Span) attribute.KeyValue { return HTTPUrlPath(s.Path) }
	case attr.ClientAddr:
		getter = func(s *Span) attribute.KeyValue { return ClientAddr(SpanPeer(s)) }
	case attr.ServerAddr:
		getter = func(s *Span) attribute.KeyValue { return ServerAddr(SpanHost(s)) }
	case attr.ServerPort:
		getter = func(s *Span) attribute.KeyValue { return ServerPort(s.HostPort) }
	case attr.RPCMethod:
		getter = func(s *Span) attribute.KeyValue { return semconv.RPCMethod(s.Path) }
	case attr.RPCSystem:
		getter = func(_ *Span) attribute.KeyValue { return semconv.RPCSystemGRPC }
	case attr.RPCGRPCStatusCode:
		getter = func(s *Span) attribute.KeyValue { return semconv.RPCGRPCStatusCodeKey.Int(s.Status) }
	case attr.DBOperation:
		getter = func(span *Span) attribute.KeyValue { return semconv.DBOperation(span.Method) }
	}
	// default: unlike the Prometheus getters, we don't check here for service name nor k8s metadata
	// because they are already attributes of the Resource instead of the metric.
	return getter, getter != nil
}

// SpanPromGetters returns the metric.Getter function that returns the
// Prometheus string value of a given attribute name.
// nolint:cyclop
func SpanPromGetters(attrName attr.Name) (metric.Getter[*Span, string], bool) {
	var getter metric.Getter[*Span, string]
	switch attrName {
	case attr.HTTPRequestMethod:
		getter = func(s *Span) string { return s.Method }
	case attr.HTTPResponseStatusCode:
		getter = func(s *Span) string { return strconv.Itoa(s.Status) }
	case attr.HTTPRoute:
		getter = func(s *Span) string { return s.Route }
	case attr.HTTPUrlPath:
		getter = func(s *Span) string { return s.Path }
	case attr.ClientAddr:
		getter = SpanPeer
	case attr.ServerAddr:
		getter = SpanHost
	case attr.ServerPort:
		getter = func(s *Span) string { return strconv.Itoa(s.HostPort) }
	case attr.RPCMethod:
		getter = func(s *Span) string { return s.Path }
	case attr.RPCSystem:
		getter = func(_ *Span) string { return "grpc" }
	case attr.RPCGRPCStatusCode:
		getter = func(s *Span) string { return strconv.Itoa(s.Status) }
	case attr.DBOperation:
		getter = func(span *Span) string { return span.Method }
	// resource metadata values below. Unlike OTEL, they are included here because they
	// belong to the metric, instead of the Resource
	case attr.ServiceName:
		getter = func(s *Span) string { return s.ServiceID.Name }
	case attr.ServiceNamespace:
		getter = func(s *Span) string { return s.ServiceID.Namespace }
	default:
		getter = func(s *Span) string { return s.ServiceID.Metadata[attrName] }
	}
	return getter, getter != nil
}

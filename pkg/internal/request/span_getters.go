package request

import (
	"strconv"

	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"

	"github.com/grafana/beyla/pkg/internal/export/attributes"
	attr "github.com/grafana/beyla/pkg/internal/export/attributes/names"
)

// SpanOTELGetters returns the attributes.Getter function that returns the
// OTEL attribute.KeyValue of a given attribute name.
// nolint:cyclop
func SpanOTELGetters(name attr.Name) (attributes.Getter[*Span, attribute.KeyValue], bool) {
	var getter attributes.Getter[*Span, attribute.KeyValue]
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
	case attr.ServiceName:
		getter = func(s *Span) attribute.KeyValue { return semconv.ServiceName(s.ServiceID.Name) }
	case attr.DBOperation:
		getter = func(span *Span) attribute.KeyValue { return DBOperationName(span.Method) }
	}
	// default: unlike the Prometheus getters, we don't check here for service name nor k8s metadata
	// because they are already attributes of the Resource instead of the attributes.
	return getter, getter != nil
}

// SpanPromGetters returns the attributes.Getter function that returns the
// Prometheus string value of a given attribute name.
// nolint:cyclop
func SpanPromGetters(attrName attr.Name) (attributes.Getter[*Span, string], bool) {
	var getter attributes.Getter[*Span, string]
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
	case attr.DBSystem:
		getter = func(span *Span) string {
			switch span.Type {
			case EventTypeSQLClient:
				return semconv.DBSystemOtherSQL.Value.AsString()
			case EventTypeRedisClient:
				return semconv.DBSystemRedis.Value.AsString()
			}
			return "unknown"
		}
	case attr.DBCollectionName:
		getter = func(span *Span) string {
			if span.Type == EventTypeSQLClient {
				return semconv.DBSystemOtherSQL.Value.AsString()
			}
			return ""
		}
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

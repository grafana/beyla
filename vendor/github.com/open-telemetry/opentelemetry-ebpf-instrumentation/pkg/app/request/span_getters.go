package request

import (
	"strconv"

	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes"
	attr "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes/names"
)

// SpanOTELGetters returns the attributes.Getter function that returns the
// OTEL attribute.KeyValue of a given attribute name.
//
//nolint:cyclop
func SpanOTELGetters(name attr.Name) (attributes.Getter[*Span, attribute.KeyValue], bool) {
	var getter attributes.Getter[*Span, attribute.KeyValue]
	switch name {
	case attr.Client:
		getter = func(s *Span) attribute.KeyValue { return ClientMetric(SpanPeer(s)) }
	case attr.ClientNamespace:
		getter = func(s *Span) attribute.KeyValue {
			if s.IsClientSpan() {
				return ClientNamespaceMetric(s.Service.UID.Namespace)
			}
			return ClientNamespaceMetric(s.OtherNamespace)
		}
	case attr.HTTPRequestMethod:
		getter = func(s *Span) attribute.KeyValue { return HTTPRequestMethod(s.Method) }
	case attr.HTTPResponseStatusCode:
		getter = func(s *Span) attribute.KeyValue { return HTTPResponseStatusCode(s.Status) }
	case attr.HTTPRoute:
		getter = func(s *Span) attribute.KeyValue { return semconv.HTTPRoute(s.Route) }
	case attr.HTTPUrlPath:
		getter = func(s *Span) attribute.KeyValue { return HTTPUrlPath(s.Path) }
	case attr.ClientAddr:
		getter = func(s *Span) attribute.KeyValue { return ClientAddr(PeerAsClient(s)) }
	case attr.ServerAddr:
		getter = func(s *Span) attribute.KeyValue {
			if s.Type == EventTypeHTTPClient {
				return ServerAddr(HTTPClientHost(s))
			}
			return ServerAddr(HostAsServer(s))
		}
	case attr.ServerPort:
		getter = func(s *Span) attribute.KeyValue { return ServerPort(s.HostPort) }
	case attr.RPCMethod:
		getter = func(s *Span) attribute.KeyValue { return semconv.RPCMethod(s.Path) }
	case attr.RPCSystem:
		getter = func(_ *Span) attribute.KeyValue { return semconv.RPCSystemGRPC }
	case attr.RPCGRPCStatusCode:
		getter = func(s *Span) attribute.KeyValue { return semconv.RPCGRPCStatusCodeKey.Int(s.Status) }
	case attr.Server:
		getter = func(s *Span) attribute.KeyValue { return ServerMetric(SpanHost(s)) }
	case attr.ServerNamespace:
		getter = func(s *Span) attribute.KeyValue {
			if s.IsClientSpan() {
				return ServerNamespaceMetric(s.OtherNamespace)
			}
			return ServerNamespaceMetric(s.Service.UID.Namespace)
		}
	case attr.ServiceInstanceID:
		getter = func(s *Span) attribute.KeyValue { return semconv.ServiceInstanceID(s.Service.UID.Instance) }
	case attr.ServiceName:
		getter = func(s *Span) attribute.KeyValue { return semconv.ServiceName(s.Service.UID.Name) }
	case attr.ServiceNamespace:
		getter = func(s *Span) attribute.KeyValue { return semconv.ServiceNamespace(s.Service.UID.Namespace) }
	case attr.SpanKind:
		getter = func(s *Span) attribute.KeyValue { return SpanKindMetric(s.ServiceGraphKind()) }
	case attr.SpanName:
		getter = func(s *Span) attribute.KeyValue { return SpanNameMetric(s.TraceName()) }
	case attr.Source:
		getter = func(_ *Span) attribute.KeyValue { return SourceMetric("beyla") }
	case attr.StatusCode:
		getter = func(s *Span) attribute.KeyValue { return StatusCodeMetric(SpanStatusCode(s)) }
	case attr.DBOperation:
		getter = func(span *Span) attribute.KeyValue { return DBOperationName(span.Method) }
	case attr.DBSystemName:
		getter = func(span *Span) attribute.KeyValue {
			switch span.Type {
			case EventTypeSQLClient:
				return DBSystemName(span.DBSystemName().Value.AsString())
			case EventTypeRedisClient, EventTypeRedisServer:
				return DBSystemName(semconv.DBSystemRedis.Value.AsString())
			}
			return DBSystemName("unknown")
		}
	case attr.ErrorType:
		getter = func(span *Span) attribute.KeyValue {
			if SpanStatusCode(span) == StatusCodeError {
				return ErrorType("error")
			}
			return ErrorType("")
		}
	case attr.MessagingSystem:
		getter = func(span *Span) attribute.KeyValue {
			if span.Type == EventTypeKafkaClient || span.Type == EventTypeKafkaServer {
				return semconv.MessagingSystem("kafka")
			}
			return semconv.MessagingSystem("unknown")
		}
	case attr.MessagingDestination:
		getter = func(span *Span) attribute.KeyValue {
			if span.Type == EventTypeKafkaClient || span.Type == EventTypeKafkaServer {
				return semconv.MessagingDestinationName(span.Path)
			}
			return semconv.MessagingDestinationName("")
		}
	case attr.CudaKernelName:
		getter = func(span *Span) attribute.KeyValue { return CudaKernel(span.Method) }
	}
	// default: unlike the Prometheus getters, we don't check here for service name nor k8s metadata
	// because they are already attributes of the Resource instead of the attributes.
	return getter, getter != nil
}

// SpanPromGetters returns the attributes.Getter function that returns the
// Prometheus string value of a given attribute name.
//
//nolint:cyclop
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
	case attr.Client, attr.ClientAddr:
		getter = PeerAsClient
	case attr.Server, attr.ServerAddr:
		getter = func(s *Span) string {
			if s.Type == EventTypeHTTPClient {
				return HTTPClientHost(s)
			}
			return HostAsServer(s)
		}
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
	case attr.ErrorType:
		getter = func(span *Span) string {
			if SpanStatusCode(span) == StatusCodeError {
				return "error"
			}
			return ""
		}
	case attr.DBSystemName:
		getter = func(span *Span) string {
			switch span.Type {
			case EventTypeSQLClient:
				return span.DBSystemName().Value.AsString()
			case EventTypeRedisClient, EventTypeRedisServer:
				return semconv.DBSystemRedis.Value.AsString()
			}
			return "unknown"
		}
	case attr.DBCollectionName:
		getter = func(span *Span) string {
			if span.Type == EventTypeSQLClient {
				return span.DBSystemName().Value.AsString()
			}
			return ""
		}
	case attr.MessagingSystem:
		getter = func(span *Span) string {
			if span.Type == EventTypeKafkaClient || span.Type == EventTypeKafkaServer {
				return "kafka"
			}
			return "unknown"
		}
	case attr.MessagingDestination:
		getter = func(span *Span) string {
			if span.Type == EventTypeKafkaClient || span.Type == EventTypeKafkaServer {
				return span.Path
			}
			return ""
		}
	case attr.ServiceInstanceID:
		getter = func(s *Span) string { return s.Service.UID.Instance }
	// resource metadata values below. Unlike OTEL, they are included here because they
	// belong to the metric, instead of the Resource
	case attr.Instance:
		getter = func(s *Span) string { return s.Service.UID.Instance }
	case attr.Job:
		getter = func(s *Span) string { return s.Service.Job() }
	case attr.ServiceName:
		getter = func(s *Span) string { return s.Service.UID.Name }
	case attr.ServiceNamespace:
		getter = func(s *Span) string { return s.Service.UID.Namespace }
	case attr.CudaKernelName:
		getter = func(s *Span) string { return s.Method }
	default:
		getter = func(s *Span) string { return s.Service.Metadata[attrName] }
	}
	return getter, getter != nil
}

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// spanOTELGetters returns the attributes.Getter function that returns the
// OTEL attribute.KeyValue of a given attribute name.
//
//nolint:cyclop
func spanOTELGetters(name attr.Name) (attributes.Getter[*Span, attribute.KeyValue], bool) {
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
		getter = func(_ *Span) attribute.KeyValue { return SourceMetric(attr.VendorPrefix) }
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
			case EventTypeMongoClient:
				return DBSystemName(semconv.DBSystemMongoDB.Value.AsString())
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
	case attr.CudaMemcpyKind:
		getter = func(span *Span) attribute.KeyValue { return CudaMemcpy(span.SubType) }
	}
	// default: unlike the Prometheus getters, we don't check here for service name nor k8s metadata
	// because they are already attributes of the Resource instead of the attributes.
	return getter, getter != nil
}

// spanPromGetters returns the attributes.Getter function that returns the
// Prometheus string value of a given attribute name.
//
//nolint:cyclop
func spanPromGetters(attrName attr.Name) (attributes.Getter[*Span, string], bool) {
	if otelGetter, ok := spanOTELGetters(attrName); ok {
		return func(span *Span) string { return otelGetter(span).Value.Emit() }, true
	}
	// unlike the OTEL getters, when the attribute is not found, we need to look for it
	// in the metadata section
	return func(s *Span) string { return s.Service.Metadata[attrName] }, true
}

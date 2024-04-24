package attr

import "go.opentelemetry.io/otel/attribute"

// Section of the attributes.allow configuration. They are metric names
// using the dot.notation and suppressing any .total .sum or .count suffix
type Section string

const (
	SectionBeylaNetworkFlow      = Section("beyla.network.flow.bytes")
	SectionHTTPServerDuration    = "http.server.request.duration"
	SectionHTTPClientDuration    = "http.client.request.duration"
	SectionRPCServerDuration     = "rpc.server.duration"
	SectionRPCClientDuration     = "rpc.client.duration"
	SectionSQLClientDuration     = "sql.client.duration"
	SectionHTTPServerRequestSize = "http.server.request.body.size"
	SectionHTTPClientRequestSize = "http.client.request.body.size"
)

// OpenTelemetry 1.23 semantic convention
const (
	HTTPRequestMethodKey      = attribute.Key("http.request.method")
	HTTPResponseStatusCodeKey = attribute.Key("http.response.status_code")
	HTTPUrlPathKey            = attribute.Key("url.path")
	HTTPUrlFullKey            = attribute.Key("url.full")
	ClientAddrKey             = attribute.Key("client.address")
	ServerAddrKey             = attribute.Key("server.address")
	ServerPortKey             = attribute.Key("server.port")
	HTTPRequestBodySizeKey    = attribute.Key("http.request.body.size")
	HTTPResponseBodySizeKey   = attribute.Key("http.response.body.size")
	SpanKindKey               = attribute.Key("span.kind")
	SpanNameKey               = attribute.Key("span.name")
	StatusCodeKey             = attribute.Key("status.code")
	SourceKey                 = attribute.Key("source")
	ServiceKey                = attribute.Key("service")
	ClientKey                 = attribute.Key("client")
	ClientNamespaceKey        = attribute.Key("client_service_namespace")
	ServerKey                 = attribute.Key("server")
	ServerNamespaceKey        = attribute.Key("server_service_namespace")
	ConnectionTypeKey         = attribute.Key("connection_type")
)

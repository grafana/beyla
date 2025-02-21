package request

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gavv/monotime"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	trace2 "go.opentelemetry.io/otel/trace"

	attr "github.com/grafana/beyla/v2/pkg/export/attributes/names"
	"github.com/grafana/beyla/v2/pkg/internal/svc"
)

type EventType uint8

// The following consts need to coincide with some C identifiers:
// EVENT_HTTP_REQUEST, EVENT_GRPC_REQUEST, EVENT_HTTP_CLIENT, EVENT_GRPC_CLIENT, EVENT_SQL_CLIENT
const (
	// EventTypeProcessAlive is an internal signal. It will be ignored by the metrics exporters.
	EventTypeProcessAlive EventType = iota
	EventTypeHTTP
	EventTypeGRPC
	EventTypeHTTPClient
	EventTypeGRPCClient
	EventTypeSQLClient
	EventTypeRedisClient
	EventTypeKafkaClient
	EventTypeRedisServer
	EventTypeKafkaServer
	EventTypeGPUKernelLaunch
	EventTypeGPUMalloc
)

const (
	metricsDetectPattern     = "/v1/metrics"
	grpcMetricsDetectPattern = "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export"
	tracesDetectPattern      = "/v1/traces"
	grpcTracesDetectPattern  = "/opentelemetry.proto.collector.trace.v1.TraceService/Export"
)

const (
	SchemeHostSeparator = ";"
)

type SQLKind uint8

const (
	DBGeneric SQLKind = iota + 1
	DBPostgres
	DBMySQL
)

//nolint:cyclop
func (t EventType) String() string {
	switch t {
	case EventTypeProcessAlive:
		return "ProcessAlive"
	case EventTypeHTTP:
		return "HTTP"
	case EventTypeGRPC:
		return "GRPC"
	case EventTypeHTTPClient:
		return "HTTPClient"
	case EventTypeGRPCClient:
		return "GRPCClient"
	case EventTypeSQLClient:
		return "SQLClient"
	case EventTypeRedisClient:
		return "RedisClient"
	case EventTypeKafkaClient:
		return "KafkaClient"
	case EventTypeRedisServer:
		return "RedisServer"
	case EventTypeKafkaServer:
		return "KafkaServer"
	case EventTypeGPUKernelLaunch:
		return "CUDALaunch"
	case EventTypeGPUMalloc:
		return "CUDAMalloc"
	default:
		return fmt.Sprintf("UNKNOWN (%d)", t)
	}
}

func (t EventType) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

type ignoreMode uint8

const (
	ignoreMetrics ignoreMode = 0x1
	ignoreTraces  ignoreMode = 0x2
)

func (m ignoreMode) String() string {
	result := ""

	if (m & ignoreMetrics) == ignoreMetrics {
		result += "Metrics"
	}
	if (m & ignoreTraces) == ignoreTraces {
		result += "Traces"
	}

	return result
}

func (m ignoreMode) MarshalText() ([]byte, error) {
	return []byte(m.String()), nil
}

const (
	MessagingPublish = "publish"
	MessagingProcess = "process"
)

type converter struct {
	clock     func() time.Time
	monoClock func() time.Duration
}

var clocks = converter{monoClock: monotime.Now, clock: time.Now}

// PidInfo stores different views of the PID of the process that generated the span
type PidInfo struct {
	// HostPID is the PID as seen by the host (root cgroup)
	HostPID uint32
	// UserID is the PID as seen by the user space.
	// Might differ from HostPID if the process is in a different namespace/cgroup/container/etc.
	UserPID uint32
	// Namespace for the PIDs
	Namespace uint32
}

// Span contains the information being submitted by the following nodes in the graph.
// It enables comfortable handling of data from Go.
// REMINDER: any attribute here must be also added to the functions SpanOTELGetters,
// SpanPromGetters and getDefinitions in pkg/export/attributes/attr_defs.go
type Span struct {
	Type           EventType      `json:"type"`
	IgnoreSpan     ignoreMode     `json:"ignoreSpan"`
	Method         string         `json:"-"`
	Path           string         `json:"-"`
	Route          string         `json:"-"`
	Peer           string         `json:"peer"`
	PeerPort       int            `json:"peerPort,string"`
	Host           string         `json:"host"`
	HostPort       int            `json:"hostPort,string"`
	Status         int            `json:"-"`
	ContentLength  int64          `json:"-"`
	RequestStart   int64          `json:"-"`
	Start          int64          `json:"-"`
	End            int64          `json:"-"`
	Service        svc.Attrs      `json:"-"`
	TraceID        trace2.TraceID `json:"traceID"`
	SpanID         trace2.SpanID  `json:"spanID"`
	ParentSpanID   trace2.SpanID  `json:"parentSpanID"`
	Flags          uint8          `json:"flags,string"`
	Pid            PidInfo        `json:"-"`
	PeerName       string         `json:"peerName"`
	HostName       string         `json:"hostName"`
	OtherNamespace string         `json:"-"`
	Statement      string         `json:"-"`
	SubType        int            `json:"-"`
}

func (s *Span) Inside(parent *Span) bool {
	return s.RequestStart >= parent.RequestStart && s.End <= parent.End
}

// InternalSignal returns whether a span is not aimed to be exported as a metric
// or a trace, because it's used to internally send messages through the pipeline.
func (s *Span) InternalSignal() bool {
	return s.Type == EventTypeProcessAlive
}

// helper attribute functions used by JSON serialization
type SpanAttributes map[string]string

func spanAttributes(s *Span) SpanAttributes {
	switch s.Type {
	case EventTypeHTTP:
		return SpanAttributes{
			"method":     s.Method,
			"status":     strconv.Itoa(s.Status),
			"url":        s.Path,
			"contentLen": strconv.FormatInt(s.ContentLength, 10),
			"route":      s.Route,
			"clientAddr": SpanPeer(s),
			"serverAddr": SpanHost(s),
			"serverPort": strconv.Itoa(s.HostPort),
		}
	case EventTypeHTTPClient:
		return SpanAttributes{
			"method":     s.Method,
			"status":     strconv.Itoa(s.Status),
			"url":        s.Path,
			"clientAddr": SpanPeer(s),
			"serverAddr": SpanHost(s),
			"serverPort": strconv.Itoa(s.HostPort),
		}
	case EventTypeGRPC:
		return SpanAttributes{
			"method":     s.Path,
			"status":     strconv.Itoa(s.Status),
			"clientAddr": SpanPeer(s),
			"serverAddr": SpanHost(s),
			"serverPort": strconv.Itoa(s.HostPort),
		}
	case EventTypeGRPCClient:
		return SpanAttributes{
			"method":     s.Path,
			"status":     strconv.Itoa(s.Status),
			"serverAddr": SpanHost(s),
			"serverPort": strconv.Itoa(s.HostPort),
		}
	case EventTypeSQLClient:
		return SpanAttributes{
			"serverAddr": SpanHost(s),
			"serverPort": strconv.Itoa(s.HostPort),
			"operation":  s.Method,
			"table":      s.Path,
			"statement":  s.Statement,
		}
	case EventTypeRedisServer:
		return SpanAttributes{
			"serverAddr": SpanHost(s),
			"serverPort": strconv.Itoa(s.HostPort),
			"operation":  s.Method,
			"statement":  s.Statement,
			"query":      s.Path,
		}
	case EventTypeKafkaServer:
		return SpanAttributes{
			"serverAddr": SpanHost(s),
			"serverPort": strconv.Itoa(s.HostPort),
			"operation":  s.Method,
			"clientId":   s.OtherNamespace,
		}
	case EventTypeGPUKernelLaunch:
		return SpanAttributes{
			"function":  s.Method,
			"callStack": s.Path,
		}
	case EventTypeGPUMalloc:
		return SpanAttributes{
			"size": strconv.FormatInt(s.ContentLength, 10),
		}
	}

	return SpanAttributes{}
}

func (s Span) MarshalJSON() ([]byte, error) {
	type JSONSpan Span

	t := s.Timings()
	start := t.RequestStart.UnixMicro()
	handlerStart := t.Start.UnixMicro()
	end := t.End.UnixMicro()
	duration := t.End.Sub(t.RequestStart)
	handlerDuration := t.End.Sub(t.Start)

	aux := struct {
		JSONSpan
		Kind              string         `json:"kind"`
		Start             int64          `json:"start,string"`
		HandlerStart      int64          `json:"handlerStart,string"`
		End               int64          `json:"end,string"`
		Duration          string         `json:"duration"`
		DurationUS        int64          `json:"durationUSec,string"`
		HandlerDuration   string         `json:"handlerDuration"`
		HandlerDurationUS int64          `json:"handlerDurationUSec,string"`
		Attributes        SpanAttributes `json:"attributes"`
	}{
		JSONSpan:          JSONSpan(s),
		Kind:              s.ServiceGraphKind(),
		Start:             start,
		HandlerStart:      handlerStart,
		End:               end,
		Duration:          duration.String(),
		DurationUS:        duration.Microseconds(),
		HandlerDuration:   handlerDuration.String(),
		HandlerDurationUS: handlerDuration.Microseconds(),
		Attributes:        spanAttributes(&s),
	}

	return json.Marshal(aux)
}

type Timings struct {
	RequestStart time.Time
	Start        time.Time
	End          time.Time
}

func (s *Span) Timings() Timings {
	now := clocks.clock()
	monoNow := clocks.monoClock()
	startDelta := monoNow - time.Duration(s.Start)
	endDelta := monoNow - time.Duration(s.End)
	goStartDelta := monoNow - time.Duration(s.RequestStart)

	return Timings{
		RequestStart: now.Add(-goStartDelta),
		Start:        now.Add(-startDelta),
		End:          now.Add(-endDelta),
	}
}

func (s *Span) IsValid() bool {
	if (len(s.Method) > 0 && !utf8.ValidString(s.Method)) ||
		(len(s.Path) > 0 && !utf8.ValidString(s.Path)) {
		return false
	}

	if s.End < s.Start {
		return false
	}

	return true
}

func (s *Span) IsClientSpan() bool {
	switch s.Type {
	case EventTypeGRPCClient, EventTypeHTTPClient, EventTypeRedisClient, EventTypeKafkaClient, EventTypeSQLClient:
		return true
	}

	return false
}

func (s *Span) setIgnoreFlag(flag ignoreMode) {
	s.IgnoreSpan |= flag
}

func (s *Span) isIgnored(flag ignoreMode) bool {
	return (s.IgnoreSpan & flag) == flag
}

func (s *Span) SetIgnoreMetrics() {
	s.setIgnoreFlag(ignoreMetrics)
}

func (s *Span) SetIgnoreTraces() {
	s.setIgnoreFlag(ignoreTraces)
}

func (s *Span) IgnoreMetrics() bool {
	return s.isIgnored(ignoreMetrics)
}

func (s *Span) IgnoreTraces() bool {
	return s.isIgnored(ignoreTraces)
}

func SpanStatusCode(span *Span) codes.Code {
	switch span.Type {
	case EventTypeHTTP, EventTypeHTTPClient:
		return HTTPSpanStatusCode(span)
	case EventTypeGRPC, EventTypeGRPCClient:
		return GrpcSpanStatusCode(span)
	case EventTypeSQLClient, EventTypeRedisClient, EventTypeRedisServer:
		if span.Status != 0 {
			return codes.Error
		}
		return codes.Unset
	}
	return codes.Unset
}

// https://opentelemetry.io/docs/specs/otel/trace/semantic_conventions/http/#status
func HTTPSpanStatusCode(span *Span) codes.Code {
	if span.Status == 0 {
		return codes.Error
	}

	if span.Status < 400 {
		return codes.Unset
	}

	if span.Status < 500 {
		if span.Type == EventTypeHTTPClient {
			return codes.Error
		}
		return codes.Unset
	}

	return codes.Error
}

// https://opentelemetry.io/docs/specs/otel/trace/semantic_conventions/rpc/#grpc-status
func GrpcSpanStatusCode(span *Span) codes.Code {
	if span.Type == EventTypeGRPCClient {
		if span.Status == int(semconv.RPCGRPCStatusCodeOk.Value.AsInt64()) {
			return codes.Unset
		}
		return codes.Error
	}

	switch int64(span.Status) {
	case semconv.RPCGRPCStatusCodeUnknown.Value.AsInt64(),
		semconv.RPCGRPCStatusCodeDeadlineExceeded.Value.AsInt64(),
		semconv.RPCGRPCStatusCodeUnimplemented.Value.AsInt64(),
		semconv.RPCGRPCStatusCodeInternal.Value.AsInt64(),
		semconv.RPCGRPCStatusCodeUnavailable.Value.AsInt64(),
		semconv.RPCGRPCStatusCodeDataLoss.Value.AsInt64():
		return codes.Error
	}

	return codes.Unset
}

func (s *Span) RequestLength() int64 {
	if s.ContentLength < 0 {
		return 0
	}

	return s.ContentLength
}

// ServiceGraphKind returns the Kind string representation that is compliant with service graph metrics specification
func (s *Span) ServiceGraphKind() string {
	switch s.Type {
	case EventTypeHTTP, EventTypeGRPC, EventTypeKafkaServer, EventTypeRedisServer:
		return "SPAN_KIND_SERVER"
	case EventTypeHTTPClient, EventTypeGRPCClient, EventTypeSQLClient, EventTypeRedisClient:
		return "SPAN_KIND_CLIENT"
	case EventTypeKafkaClient:
		switch s.Method {
		case MessagingPublish:
			return "SPAN_KIND_PRODUCER"
		case MessagingProcess:
			return "SPAN_KIND_CONSUMER"
		}
	}
	return "SPAN_KIND_INTERNAL"
}

func (s *Span) TraceName() string {
	switch s.Type {
	case EventTypeHTTP:
		name := s.Method
		if s.Route != "" {
			name += " " + s.Route
		}
		return name
	case EventTypeGRPC, EventTypeGRPCClient:
		return s.Path
	case EventTypeHTTPClient:
		return s.Method
	case EventTypeSQLClient:
		operation := s.Method
		if operation == "" {
			return "SQL"
		}
		table := s.Path
		if table != "" {
			operation += " " + table
		}
		return operation
	case EventTypeRedisClient, EventTypeRedisServer:
		if s.Method == "" {
			return "REDIS"
		}
		return s.Method
	case EventTypeKafkaClient, EventTypeKafkaServer:
		if s.Path == "" {
			return s.Method
		}
		return fmt.Sprintf("%s %s", s.Path, s.Method)
	}
	return ""
}

func (s *Span) isHTTPOrGRPCClient() bool {
	return s.Type == EventTypeHTTPClient || s.Type == EventTypeGRPCClient
}

func (s *Span) isMetricsExportURL() bool {
	switch s.Type {
	case EventTypeGRPCClient:
		return strings.HasPrefix(s.Path, grpcMetricsDetectPattern)
	case EventTypeHTTPClient:
		return strings.HasSuffix(s.Path, metricsDetectPattern)
	default:
		return false
	}
}

func (s *Span) isTracesExportURL() bool {
	switch s.Type {
	case EventTypeGRPCClient:
		return strings.HasPrefix(s.Path, grpcTracesDetectPattern)
	case EventTypeHTTPClient:
		return strings.HasSuffix(s.Path, tracesDetectPattern)
	default:
		return false
	}
}

func (s *Span) IsExportMetricsSpan() bool {
	// check if it's a successful client call
	if !s.isHTTPOrGRPCClient() || (SpanStatusCode(s) != codes.Unset) {
		return false
	}

	return s.isMetricsExportURL()
}

func (s *Span) IsExportTracesSpan() bool {
	// check if it's a successful client call
	if !s.isHTTPOrGRPCClient() || (SpanStatusCode(s) != codes.Unset) {
		return false
	}

	return s.isTracesExportURL()
}

func (s *Span) IsSelfReferenceSpan() bool {
	return s.Peer == s.Host && (s.Service.UID.Namespace == s.OtherNamespace || s.OtherNamespace == "")
}

// TODO: replace by semconv.DBSystemPostgreSQL, semconv.DBSystemMySQL, semconv.DBSystemRedis when we
// update semantic conventions library to 1.30.0
var (
	dbSystemPostgreSQL = attribute.String(string(attr.DBSystemName), semconv.DBSystemPostgreSQL.Value.AsString())
	dbSystemMySQL      = attribute.String(string(attr.DBSystemName), semconv.DBSystemMySQL.Value.AsString())
	dbSystemOtherSQL   = attribute.String(string(attr.DBSystemName), semconv.DBSystemOtherSQL.Value.AsString())
)

func (s *Span) DBSystemName() attribute.KeyValue {
	if s.Type == EventTypeSQLClient {
		switch s.SubType {
		case int(DBPostgres):
			return dbSystemPostgreSQL
		case int(DBMySQL):
			return dbSystemMySQL
		}
	}

	return dbSystemOtherSQL
}

func (s *Span) HasOriginalHost() bool {
	schemeHost := strings.Split(s.Statement, SchemeHostSeparator)
	return len(schemeHost) > 1 && schemeHost[1] != ""
}

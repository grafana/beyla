package request

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/gavv/monotime"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	trace2 "go.opentelemetry.io/otel/trace"

	"github.com/grafana/beyla/pkg/internal/svc"
)

type EventType uint8

// The following consts need to coincide with some C identifiers:
// EVENT_HTTP_REQUEST, EVENT_GRPC_REQUEST, EVENT_HTTP_CLIENT, EVENT_GRPC_CLIENT, EVENT_SQL_CLIENT
const (
	EventTypeHTTP EventType = iota + 1
	EventTypeGRPC
	EventTypeHTTPClient
	EventTypeGRPCClient
	EventTypeSQLClient
	EventTypeRedisClient
	EventTypeKafkaClient
	EventTypeRedisServer
	EventTypeKafkaServer
)

func (t EventType) String() string {
	switch t {
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
	default:
		return fmt.Sprintf("UNKNOWN (%d)", t)
	}
}

func (t EventType) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

type IgnoreMode uint8

const (
	IgnoreMetrics IgnoreMode = iota + 1
	IgnoreTraces
)

func (m IgnoreMode) String() string {
	switch m {
	case IgnoreMetrics:
		return "Metrics"
	case IgnoreTraces:
		return "Traces"
	case 0:
		return "(none)"
	default:
		return fmt.Sprintf("UNKNOWN (%d)", m)
	}
}

func (m IgnoreMode) MarshalText() ([]byte, error) {
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
	IgnoreSpan     IgnoreMode     `json:"ignoreSpan"`
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
	ServiceID      svc.ID         `json:"-"` // TODO: rename to Service or ResourceAttrs
	TraceID        trace2.TraceID `json:"traceID"`
	SpanID         trace2.SpanID  `json:"spanID"`
	ParentSpanID   trace2.SpanID  `json:"parentSpanID"`
	Flags          uint8          `json:"flags,string"`
	Pid            PidInfo        `json:"-"`
	PeerName       string         `json:"peerName"`
	HostName       string         `json:"hostName"`
	OtherNamespace string         `json:"-"`
	Statement      string         `json:"-"`
}

func (s *Span) Inside(parent *Span) bool {
	return s.RequestStart >= parent.RequestStart && s.End <= parent.End
}

const (
	kClient   = "CLIENT"
	kServer   = "SERVER"
	kProducer = "PRODUCER"
	kConsumer = "CONSUMER"
	kInternal = "INTERNAL"
)

func kindString(span *Span) string {
	switch span.Type {
	case EventTypeHTTP, EventTypeGRPC, EventTypeKafkaServer, EventTypeRedisServer:
		return kServer
	case EventTypeHTTPClient, EventTypeGRPCClient, EventTypeSQLClient, EventTypeRedisClient:
		return kClient
	case EventTypeKafkaClient:
		switch span.Method {
		case MessagingPublish:
			return kProducer
		case MessagingProcess:
			return kConsumer
		}
	}
	return kInternal
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
		Kind:              kindString(&s),
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

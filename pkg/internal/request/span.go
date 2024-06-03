package request

import (
	"time"
	"unicode/utf8"

	"github.com/gavv/monotime"
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
)

type IgnoreMode uint8

const (
	IgnoreMetrics IgnoreMode = iota + 1
	IgnoreTraces
)

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
// SpanPromGetters and getDefinitions in pkg/internal/export/metric/definitions.go
type Span struct {
	Type           EventType
	IgnoreSpan     IgnoreMode
	ID             uint64
	Method         string
	Path           string
	Route          string
	Peer           string
	Host           string
	HostPort       int
	Status         int
	ContentLength  int64
	RequestStart   int64
	Start          int64
	End            int64
	ServiceID      svc.ID // TODO: rename to Service or ResourceAttrs
	TraceID        trace2.TraceID
	SpanID         trace2.SpanID
	ParentSpanID   trace2.SpanID
	Flags          uint8
	Pid            PidInfo
	PeerName       string
	HostName       string
	OtherNamespace string
	Statement      string
}

func (s *Span) Inside(parent *Span) bool {
	return s.RequestStart >= parent.RequestStart && s.End <= parent.End
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
	case EventTypeGRPCClient:
		fallthrough
	case EventTypeHTTPClient:
		fallthrough
	case EventTypeSQLClient:
		return true
	}

	return false
}

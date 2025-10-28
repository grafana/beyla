// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gavv/monotime"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
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
	EventTypeMongoClient
	EventTypeManualSpan
	EventTypeGPUKernelLaunch
	EventTypeGPUMalloc
	EventTypeGPUMemcpy
	EventTypeFailedConnect
)

const (
	envOTLPProtocol        = "OTEL_EXPORTER_OTLP_PROTOCOL"
	envOTLPTracesProtocol  = "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"
	envOTLPMetricsProtocol = "OTEL_EXPORTER_OTLP_METRICS_PROTOCOL"
	envOTLPEndpoint        = "OTEL_EXPORTER_OTLP_ENDPOINT"
	envOTLPTracesEndpoint  = "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"
	envOTLPMetricsEndpoint = "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"
	otlpGrpcProtocol       = "grpc"
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

const (
	HTTPSubtypeNone          = 0 // http
	HTTPSubtypeGraphQL       = 1 // http + graphql
	HTTPSubtypeElasticsearch = 2 // http + elasticsearch
	HTTPSubtypeAWSS3         = 3 // http + aws s3
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
	case EventTypeGPUMemcpy:
		return "CUDAMemcpy"
	case EventTypeMongoClient:
		return "MongoClient"
	case EventTypeManualSpan:
		return "CUSTOM"
	case EventTypeFailedConnect:
		return "CONNECTION ERR"
	default:
		return fmt.Sprintf("UNKNOWN (%d)", t)
	}
}

func (t EventType) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
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

type DBError struct {
	ErrorCode   string
	Description string
}

type SQLError struct {
	Code     uint16 `json:"code"`
	SQLState string `json:"sqlState"`
	Message  string `json:"message"`
}

type MessagingInfo struct {
	Offset    int64 `json:"offset"`
	Partition int   `json:"partition"`
}

type GraphQL struct {
	Document      string `json:"document"`
	OperationName string `json:"operationName"`
	OperationType string `json:"operationType"`
}

type Elasticsearch struct {
	DBCollectionName string `json:"dbCollectionName"`
	NodeName         string `json:"nodeName"`
	DBOperationName  string `json:"dbOperationName"`
	DBQueryText      string `json:"dbQueryText"`
}

type AWS struct {
	// https://opentelemetry.io/docs/specs/semconv/object-stores/s3/
	S3 AWSS3 `json:"s3"`
}

type AWSS3 struct {
	RequestID         string `json:"requestId"`
	ExtendedRequestID string `json:"extendedRequestId"`
	Region            string `json:"region"`
	Method            string `json:"method"`
	Bucket            string `json:"bucket"`
	Key               string `json:"key"`
}

// Span contains the information being submitted by the following nodes in the graph.
// It enables comfortable handling of data from Go.
// REMINDER: any attribute here must be also added to the functions SpanOTELGetters,
// SpanPromGetters and getDefinitions in pkg/export/attributes/attr_defs.go
type Span struct {
	Type           EventType      `json:"type"`
	Flags          uint8          `json:"-"`
	Method         string         `json:"-"`
	Path           string         `json:"-"`
	Route          string         `json:"-"`
	Peer           string         `json:"peer"`
	PeerPort       int            `json:"peerPort,string"`
	Host           string         `json:"host"`
	HostPort       int            `json:"hostPort,string"`
	Status         int            `json:"-"`
	ResponseLength int64          `json:"-"`
	ContentLength  int64          `json:"-"`
	RequestStart   int64          `json:"-"`
	Start          int64          `json:"-"`
	End            int64          `json:"-"`
	Service        svc.Attrs      `json:"-"`
	TraceID        trace.TraceID  `json:"traceID"`
	SpanID         trace.SpanID   `json:"spanID"`
	ParentSpanID   trace.SpanID   `json:"parentSpanID"`
	TraceFlags     uint8          `json:"traceFlags,string"`
	Pid            PidInfo        `json:"-"`
	PeerName       string         `json:"peerName"`
	HostName       string         `json:"hostName"`
	OtherNamespace string         `json:"-"`
	Statement      string         `json:"-"`
	SubType        int            `json:"-"`
	DBError        DBError        `json:"-"`
	DBNamespace    string         `json:"-"`
	SQLCommand     string         `json:"-"`
	SQLError       *SQLError      `json:"-"`
	MessagingInfo  *MessagingInfo `json:"-"`
	GraphQL        *GraphQL       `json:"-"`
	Elasticsearch  *Elasticsearch `json:"-"`
	AWS            *AWS           `json:"-"`

	// OverrideTraceName is set under some conditions, like spanmetrics reaching the maximum
	// cardinality for trace names.
	OverrideTraceName string `json:"-"`
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
		attrs := SpanAttributes{
			"method":      s.Method,
			"status":      strconv.Itoa(s.Status),
			"url":         s.Path,
			"contentLen":  strconv.FormatInt(s.ContentLength, 10),
			"responseLen": strconv.FormatInt(s.ResponseLength, 10),
			"route":       s.Route,
			"clientAddr":  SpanPeer(s),
			"serverAddr":  SpanHost(s),
			"serverPort":  strconv.Itoa(s.HostPort),
		}
		if s.SubType == HTTPSubtypeGraphQL && s.GraphQL != nil {
			attrs["graphqlDocument"] = s.GraphQL.Document
			attrs["graphqlOperationName"] = s.GraphQL.OperationName
			attrs["graphqlOperationType"] = s.GraphQL.OperationType
		}
		return attrs
	case EventTypeHTTPClient:
		attrs := SpanAttributes{
			"method":     s.Method,
			"status":     strconv.Itoa(s.Status),
			"url":        s.Path,
			"clientAddr": SpanPeer(s),
			"serverAddr": SpanHost(s),
			"serverPort": strconv.Itoa(s.HostPort),
		}
		if s.SubType == HTTPSubtypeElasticsearch && s.Elasticsearch != nil {
			attrs["dbCollectionName"] = s.Elasticsearch.DBCollectionName
			attrs["nodeName"] = s.Elasticsearch.NodeName
			attrs["dbOperationName"] = s.Elasticsearch.DBOperationName
			attrs["dbQueryText"] = s.Elasticsearch.DBQueryText
		}
		if s.SubType == HTTPSubtypeAWSS3 && s.AWS != nil {
			attrs["awsRequestID"] = s.AWS.S3.RequestID
			attrs["awsExtendedRequestID"] = s.AWS.S3.ExtendedRequestID
			attrs["awsRegion"] = s.AWS.S3.Region
			attrs["awsS3Method"] = s.AWS.S3.Method
			attrs["awsS3Bucket"] = s.AWS.S3.Bucket
			attrs["awsS3Key"] = s.AWS.S3.Key
		}
		return attrs
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
		var (
			code              uint16
			sqlState, message string
		)

		if s.SQLError != nil {
			code = s.SQLError.Code
			sqlState = s.SQLError.SQLState
			message = s.SQLError.Message
		}

		return SpanAttributes{
			"serverAddr":       SpanHost(s),
			"serverPort":       strconv.Itoa(s.HostPort),
			"operation":        s.Method,
			"table":            s.Path,
			"statement":        s.Statement,
			"sqlCommand":       s.SQLCommand,
			"errorCode":        strconv.FormatUint(uint64(code), 10),
			"sqlState":         sqlState,
			"errorMessage":     message,
			"errorDescription": s.SQLErrorDescription(),
		}
	case EventTypeRedisServer:
		return SpanAttributes{
			"serverAddr": SpanHost(s),
			"serverPort": strconv.Itoa(s.HostPort),
			"operation":  s.Method,
			"statement":  s.Statement,
			"query":      s.Path,
		}
	case EventTypeKafkaServer, EventTypeKafkaClient:
		attrs := SpanAttributes{
			"serverAddr": SpanHost(s),
			"serverPort": strconv.Itoa(s.HostPort),
			"operation":  s.Method,
			"clientId":   s.Statement,
			"topic":      s.Path,
		}
		if s.MessagingInfo != nil {
			attrs["partition"] = strconv.FormatUint(uint64(s.MessagingInfo.Partition), 10)
			if s.Method == MessagingProcess {
				attrs["offset"] = strconv.FormatUint(uint64(s.MessagingInfo.Offset), 10)
			}
		}
		return attrs
	case EventTypeGPUKernelLaunch:
		return SpanAttributes{
			"function":  s.Method,
			"callStack": s.Path,
			"gridSize":  strconv.FormatInt(s.ContentLength, 10),
			"blockSize": strconv.Itoa(s.SubType),
		}
	case EventTypeGPUMalloc:
		return SpanAttributes{
			"size": strconv.FormatInt(s.ContentLength, 10),
		}
	case EventTypeMongoClient:
		return SpanAttributes{
			"serverAddr": SpanHost(s),
			"serverPort": strconv.Itoa(s.HostPort),
			"operation":  s.Method,
			"table":      s.Path,
		}
	}

	return SpanAttributes{}
}

func (s *Span) SQLErrorDescription() string {
	if s.SQLError == nil {
		return ""
	}

	var codeString string
	if s.SQLError.Code == 0 {
		codeString = "NA"
	} else {
		codeString = strconv.FormatUint(uint64(s.SQLError.Code), 10)
	}

	if s.SQLCommand == "" {
		return fmt.Sprintf(
			"SQL Server errored: error_code=%s sql_state=%s message=%s",
			codeString, s.SQLError.SQLState, s.SQLError.Message,
		)
	}

	return fmt.Sprintf(
		"SQL Server errored for command 'COM_%s': error_code=%s sql_state=%s message=%s",
		s.SQLCommand, codeString, s.SQLError.SQLState, s.SQLError.Message,
	)
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
	case EventTypeGRPCClient, EventTypeHTTPClient, EventTypeRedisClient, EventTypeKafkaClient, EventTypeSQLClient, EventTypeMongoClient, EventTypeFailedConnect:
		return true
	}

	return false
}

func (s *Span) IsHTTPSpan() bool {
	return s.Type == EventTypeHTTP || s.Type == EventTypeHTTPClient
}

const (
	StatusCodeUnset = "STATUS_CODE_UNSET"
	StatusCodeError = "STATUS_CODE_ERROR"
	StatusCodeOk    = "STATUS_CODE_OK"
)

func SpanStatusCode(span *Span) string {
	switch span.Type {
	case EventTypeHTTP, EventTypeHTTPClient:
		return HTTPSpanStatusCode(span)
	case EventTypeGRPC, EventTypeGRPCClient:
		return GrpcSpanStatusCode(span)
	case EventTypeSQLClient, EventTypeRedisClient, EventTypeRedisServer, EventTypeMongoClient:
		if span.Status != 0 {
			return StatusCodeError
		}
		return StatusCodeUnset
	case EventTypeManualSpan:
		switch span.Status {
		case int(codes.Error):
			return StatusCodeError
		case int(codes.Ok):
			return StatusCodeOk
		}
		return StatusCodeUnset
	case EventTypeFailedConnect:
		return StatusCodeError
	}
	return StatusCodeUnset
}

func SpanStatusMessage(span *Span) string {
	switch span.Type {
	case EventTypeRedisClient, EventTypeRedisServer, EventTypeMongoClient:
		if span.Status != 0 && span.DBError.Description != "" {
			return span.DBError.Description
		}
	case EventTypeSQLClient:
		if span.Status != 0 && span.SQLError != nil {
			return span.SQLErrorDescription()
		}
	case EventTypeManualSpan:
		return span.Path
	}
	return ""
}

// HTTPSpanStatusCode https://opentelemetry.io/docs/specs/otel/trace/semantic_conventions/http/#status
func HTTPSpanStatusCode(span *Span) string {
	if span.Status == 0 {
		return StatusCodeError
	}

	if span.Type == EventTypeHTTPClient {
		if span.Status < 400 {
			return StatusCodeUnset
		}
	} else if span.Status < 500 {
		return StatusCodeUnset
	}

	return StatusCodeError
}

var (
	grpcStatusCodeOK               = int(semconv.RPCGRPCStatusCodeOk.Value.AsInt64())
	grpcStatusCodeUnknown          = int(semconv.RPCGRPCStatusCodeUnknown.Value.AsInt64())
	grpcStatusCodeDeadlineExceeded = int(semconv.RPCGRPCStatusCodeDeadlineExceeded.Value.AsInt64())
	grpcStatusCodeUnimplemented    = int(semconv.RPCGRPCStatusCodeUnimplemented.Value.AsInt64())
	grpcStatusCodeInternal         = int(semconv.RPCGRPCStatusCodeInternal.Value.AsInt64())
	grpcStatusCodeUnavailable      = int(semconv.RPCGRPCStatusCodeUnavailable.Value.AsInt64())
	grpcStatusCodeDataLoss         = int(semconv.RPCGRPCStatusCodeDataLoss.Value.AsInt64())
)

// GrpcSpanStatusCode https://opentelemetry.io/docs/specs/otel/trace/semantic_conventions/rpc/#grpc-status
func GrpcSpanStatusCode(span *Span) string {
	if span.Type == EventTypeGRPCClient && span.Status != grpcStatusCodeOK {
		return StatusCodeError
	}
	switch span.Status {
	case grpcStatusCodeOK:
		return StatusCodeUnset
	case grpcStatusCodeUnknown, grpcStatusCodeDeadlineExceeded, grpcStatusCodeUnimplemented,
		grpcStatusCodeInternal, grpcStatusCodeUnavailable, grpcStatusCodeDataLoss:
		return StatusCodeError
	}

	return StatusCodeUnset
}

func (s *Span) RequestBodyLength() int64 {
	// The value -1 indicates that the length is unknown.
	if s.ContentLength < 0 {
		return 0
	}

	return s.ContentLength
}

func (s *Span) ResponseBodyLength() int64 {
	// The value -1 indicates that the length is unknown.
	if s.ResponseLength < 0 {
		return 0
	}

	return s.ResponseLength
}

// ServiceGraphKind returns the Kind string representation that is compliant with service graph metrics specification
func (s *Span) ServiceGraphKind() string {
	switch s.Type {
	case EventTypeHTTP, EventTypeGRPC, EventTypeKafkaServer, EventTypeRedisServer:
		return "SPAN_KIND_SERVER"
	case EventTypeHTTPClient, EventTypeGRPCClient, EventTypeSQLClient, EventTypeRedisClient, EventTypeMongoClient, EventTypeFailedConnect:
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
	if s.OverrideTraceName != "" {
		return s.OverrideTraceName
	}
	switch s.Type {
	case EventTypeHTTP, EventTypeHTTPClient:
		if s.Type == EventTypeHTTP && s.SubType == HTTPSubtypeGraphQL && s.GraphQL != nil {
			if s.GraphQL.OperationType != "" {
				return "GraphQL " + s.GraphQL.OperationType
			} else {
				return "GraphQL Operation"
			}
		}
		if s.Type == EventTypeHTTPClient && s.SubType == HTTPSubtypeElasticsearch && s.Elasticsearch != nil {
			dbOperationName := s.Elasticsearch.DBOperationName
			// https://opentelemetry.io/docs/specs/semconv/database/database-spans/#name
			if dbOperationName == "" {
				return "elasticsearch"
			}
			switch {
			case s.Elasticsearch.DBCollectionName != "":
				return dbOperationName + " " + s.Elasticsearch.DBCollectionName
			case s.DBNamespace != "":
				return dbOperationName + " " + s.DBNamespace
			case s.Host != "" && s.HostPort != 0:
				return dbOperationName + " " + s.Host + ":" + strconv.Itoa(s.HostPort)
			default:
				return dbOperationName
			}
		}

		if s.Type == EventTypeHTTPClient && s.SubType == HTTPSubtypeAWSS3 && s.AWS != nil {
			if s.AWS.S3.Method != "" {
				return "s3." + s.AWS.S3.Method
			} else {
				return "s3.Operation"
			}
		}

		name := s.Method
		if s.Route != "" {
			name += " " + s.Route
		}
		return name
	case EventTypeGRPC, EventTypeGRPCClient:
		return s.Path
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
		return s.Method + " " + s.Path
	case EventTypeMongoClient:
		if s.Path != "" && s.Method != "" {
			// TODO for database operations like listCollections, we need to use s.DbNamespace instead of s.Path
			return s.Method + " " + s.Path
		}
		if s.Path != "" {
			return s.Path
		}
		if s.Method != "" {
			return s.Method
		}
		return semconv.DBSystemMongoDB.Value.AsString()
	case EventTypeManualSpan:
		return s.Method
	case EventTypeFailedConnect:
		return "CONNECT"
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

func (s *Span) sendsOnDefaultGrpcOtelPort(defaultOtlpGRPCPort int) bool {
	otlpPort, ok := s.portFromEndpointEnvVar(envOTLPEndpoint)
	if ok {
		return otlpPort == s.PeerPort
	}
	return s.PeerPort == defaultOtlpGRPCPort
}

func (s *Span) sendsTracesOnGrpcOtelPort(defaultOtlpGRPCPort int) bool {
	otlpTracesProtocol, ok := s.Service.EnvVars[envOTLPTracesProtocol]
	if ok && otlpTracesProtocol != otlpGrpcProtocol {
		return false
	}
	otlpProtocol, ok := s.Service.EnvVars[envOTLPProtocol]
	if ok && otlpProtocol != otlpGrpcProtocol {
		return false
	}
	otlpTracesPort, ok := s.portFromEndpointEnvVar(envOTLPTracesEndpoint)
	if ok {
		return otlpTracesPort == s.PeerPort
	}
	return s.sendsOnDefaultGrpcOtelPort(defaultOtlpGRPCPort)
}

func (s *Span) sendsMetricsOnOtelPort(defaultOtlpGRPCPort int) bool {
	switch s.Type {
	case EventTypeGRPCClient:
		return s.sendsMetricsOnGrpcOtelPort(defaultOtlpGRPCPort)
	default:
		return false
	}
}

func (s *Span) sendsTracesOnOtelPort(defaultOtlpGRPCPort int) bool {
	switch s.Type {
	case EventTypeGRPCClient:
		return s.sendsTracesOnGrpcOtelPort(defaultOtlpGRPCPort)
	default:
		return false
	}
}

func (s *Span) sendsMetricsOnGrpcOtelPort(defaultOtlpGRPCPort int) bool {
	otlpMetricsProtocol, ok := s.Service.EnvVars[envOTLPMetricsProtocol]
	if ok && otlpMetricsProtocol != otlpGrpcProtocol {
		return false
	}
	otlpProtocol, ok := s.Service.EnvVars[envOTLPProtocol]
	if ok && otlpProtocol != otlpGrpcProtocol {
		return false
	}
	otlpMetricsPort, ok := s.portFromEndpointEnvVar(envOTLPMetricsEndpoint)
	if ok {
		return otlpMetricsPort == s.PeerPort
	}
	return s.sendsOnDefaultGrpcOtelPort(defaultOtlpGRPCPort)
}

func (s *Span) portFromEndpointEnvVar(envVarName string) (int, bool) {
	endpoint, ok := s.Service.EnvVars[envVarName]
	if !ok {
		return 0, false
	}
	parsedURL, err := url.Parse(endpoint)
	if err != nil || parsedURL == nil {
		return 0, false
	}
	port, err := strconv.Atoi(parsedURL.Port())
	if err != nil {
		return 0, false
	}
	return port, true
}

func (s *Span) IsExportMetricsSpan(defaultOtlpGRPCPort int) bool {
	// check if it's a successful client call
	if !s.isHTTPOrGRPCClient() || (SpanStatusCode(s) != StatusCodeUnset) {
		return false
	}

	return s.isMetricsExportURL() || s.sendsMetricsOnOtelPort(defaultOtlpGRPCPort)
}

func (s *Span) IsExportTracesSpan(defaultOtlpGRPCPort int) bool {
	// check if it's a successful client call
	if !s.isHTTPOrGRPCClient() || (SpanStatusCode(s) != StatusCodeUnset) {
		return false
	}

	return s.isTracesExportURL() || s.sendsTracesOnOtelPort(defaultOtlpGRPCPort)
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

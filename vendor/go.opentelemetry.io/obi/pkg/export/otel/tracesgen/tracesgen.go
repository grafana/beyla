// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracesgen

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"time"

	expirable2 "github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.25.0"
	trace2 "go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/idgen"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
)

type TraceSpanAndAttributes struct {
	Span       *request.Span
	Attributes []attribute.KeyValue
}

type SpanAttr struct {
	ValLength uint16
	Vtype     uint8
	Reserved  uint8
	Key       [32]uint8
	Value     [128]uint8
}

// UserSelectedAttributes must remain public for collectors embedding OBI
func UserSelectedAttributes(selectorCfg *attributes.SelectorConfig) (map[attr.Name]struct{}, error) {
	// Get user attributes
	attribProvider, err := attributes.NewAttrSelector(attributes.GroupTraces, selectorCfg)
	if err != nil {
		return nil, err
	}
	traceAttrsArr := attribProvider.For(attributes.Traces)
	traceAttrs := make(map[attr.Name]struct{})
	for _, a := range traceAttrsArr {
		traceAttrs[a] = struct{}{}
	}

	return traceAttrs, err
}

// GroupSpans must remain public for collectors embedding OBI
func GroupSpans(ctx context.Context, spans []request.Span, traceAttrs map[attr.Name]struct{}, sampler trace.Sampler, is instrumentations.InstrumentationSelection) map[svc.UID][]TraceSpanAndAttributes {
	spanGroups := map[svc.UID][]TraceSpanAndAttributes{}

	for i := range spans {
		span := &spans[i]
		if span.InternalSignal() {
			continue
		}
		if SpanDiscarded(span, is) {
			continue
		}

		finalAttrs := TraceAttributesSelector(span, traceAttrs)

		spanSampler := func() trace.Sampler {
			if span.Service.Sampler != nil {
				return span.Service.Sampler
			}

			return sampler
		}

		sr := spanSampler().ShouldSample(trace.SamplingParameters{
			ParentContext: ctx,
			Name:          span.TraceName(),
			TraceID:       span.TraceID,
			Kind:          spanKind(span),
			Attributes:    finalAttrs,
		})

		if sr.Decision == trace.Drop {
			continue
		}

		group, ok := spanGroups[span.Service.UID]
		if !ok {
			group = []TraceSpanAndAttributes{}
		}
		group = append(group, TraceSpanAndAttributes{Span: span, Attributes: finalAttrs})
		spanGroups[span.Service.UID] = group
	}

	return spanGroups
}

// GenerateTracesWithAttributes must remain public for collectors embedding OBI
func GenerateTracesWithAttributes(
	cache *expirable2.LRU[svc.UID, []attribute.KeyValue],
	svc *svc.Attrs,
	envResourceAttrs []attribute.KeyValue,
	hostID string,
	spans []TraceSpanAndAttributes,
	reporterName string,
	extraResAttrs ...attribute.KeyValue,
) ptrace.Traces {
	traces := ptrace.NewTraces()
	rs := traces.ResourceSpans().AppendEmpty()
	resourceAttrs := TraceAppResourceAttrs(cache, hostID, svc)
	resourceAttrs = append(resourceAttrs, envResourceAttrs...)
	resourceAttrsMap := AttrsToMap(resourceAttrs)
	resourceAttrsMap.PutStr(string(semconv.OTelLibraryNameKey), reporterName)
	addAttrsToMap(extraResAttrs, resourceAttrsMap)
	resourceAttrsMap.MoveTo(rs.Resource().Attributes())

	for _, spanWithAttributes := range spans {
		span := spanWithAttributes.Span
		attrs := spanWithAttributes.Attributes

		ss := rs.ScopeSpans().AppendEmpty()

		t := span.Timings()
		start := spanStartTime(t)
		hasSubSpans := t.Start.After(start)

		traceID := pcommon.TraceID(span.TraceID)
		spanID := pcommon.SpanID(idgen.RandomSpanID())
		// This should never happen
		if traceID.IsEmpty() {
			traceID = pcommon.TraceID(idgen.RandomTraceID())
		}

		if hasSubSpans {
			createSubSpans(span, spanID, traceID, &ss, t)
		} else if span.SpanID.IsValid() {
			spanID = pcommon.SpanID(span.SpanID)
		}

		// Create a parent span for the whole request session
		s := ss.Spans().AppendEmpty()
		s.SetName(span.TraceName())
		s.SetKind(ptrace.SpanKind(spanKind(span)))
		s.SetStartTimestamp(pcommon.NewTimestampFromTime(start))

		// Set trace and span IDs
		s.SetSpanID(spanID)
		s.SetTraceID(traceID)
		if span.ParentSpanID.IsValid() {
			s.SetParentSpanID(pcommon.SpanID(span.ParentSpanID))
		}

		// Set span attributes
		m := AttrsToMap(attrs)
		m.MoveTo(s.Attributes())

		// Set status code
		statusCode := CodeToStatusCode(request.SpanStatusCode(span))
		s.Status().SetCode(statusCode)
		statusMessage := request.SpanStatusMessage(span)
		if statusMessage != "" {
			s.Status().SetMessage(statusMessage)
		}
		s.SetEndTimestamp(pcommon.NewTimestampFromTime(t.End))
	}
	return traces
}

func SpanDiscarded(span *request.Span, is instrumentations.InstrumentationSelection) bool {
	return request.IgnoreTraces(span) || span.Service.ExportsOTelTraces() || !acceptSpan(is, span)
}

// createSubSpans creates the internal spans for a request.Span
func createSubSpans(span *request.Span, parentSpanID pcommon.SpanID, traceID pcommon.TraceID, ss *ptrace.ScopeSpans, t request.Timings) {
	// Create a child span showing the queue time
	spQ := ss.Spans().AppendEmpty()
	spQ.SetName("in queue")
	spQ.SetStartTimestamp(pcommon.NewTimestampFromTime(t.RequestStart))
	spQ.SetKind(ptrace.SpanKindInternal)
	spQ.SetEndTimestamp(pcommon.NewTimestampFromTime(t.Start))
	spQ.SetTraceID(traceID)
	spQ.SetSpanID(pcommon.SpanID(idgen.RandomSpanID()))
	spQ.SetParentSpanID(parentSpanID)

	// Create a child span showing the processing time
	spP := ss.Spans().AppendEmpty()
	spP.SetName("processing")
	spP.SetStartTimestamp(pcommon.NewTimestampFromTime(t.Start))
	spP.SetKind(ptrace.SpanKindInternal)
	spP.SetEndTimestamp(pcommon.NewTimestampFromTime(t.End))
	spP.SetTraceID(traceID)
	if span.SpanID.IsValid() {
		spP.SetSpanID(pcommon.SpanID(span.SpanID))
	} else {
		spP.SetSpanID(pcommon.SpanID(idgen.RandomSpanID()))
	}
	spP.SetParentSpanID(parentSpanID)
}

var emptyUID = svc.UID{}

func TraceAppResourceAttrs(cache *expirable2.LRU[svc.UID, []attribute.KeyValue], hostID string, service *svc.Attrs) []attribute.KeyValue {
	// TODO: remove?
	if service.UID == emptyUID {
		return otelcfg.GetAppResourceAttrs(hostID, service)
	}

	attrs, ok := cache.Get(service.UID)
	if ok {
		return attrs
	}
	attrs = otelcfg.GetAppResourceAttrs(hostID, service)
	cache.Add(service.UID, attrs)

	return attrs
}

// AttrsToMap converts a slice of attribute.KeyValue to a pcommon.Map
func AttrsToMap(attrs []attribute.KeyValue) pcommon.Map {
	m := pcommon.NewMap()
	addAttrsToMap(attrs, m)
	return m
}

func addAttrsToMap(attrs []attribute.KeyValue, dst pcommon.Map) {
	dst.EnsureCapacity(dst.Len() + len(attrs))
	for _, attr := range attrs {
		switch v := attr.Value.AsInterface().(type) {
		case string:
			dst.PutStr(string(attr.Key), v)
		case int64:
			dst.PutInt(string(attr.Key), v)
		case float64:
			dst.PutDouble(string(attr.Key), v)
		case bool:
			dst.PutBool(string(attr.Key), v)
		}
	}
}

// CodeToStatusCode converts a codes.Code to a ptrace.StatusCode
func CodeToStatusCode(code string) ptrace.StatusCode {
	switch code {
	case request.StatusCodeUnset:
		return ptrace.StatusCodeUnset
	case request.StatusCodeError:
		return ptrace.StatusCodeError
	case request.StatusCodeOk:
		return ptrace.StatusCodeOk
	}
	return ptrace.StatusCodeUnset
}

func acceptSpan(is instrumentations.InstrumentationSelection, span *request.Span) bool {
	switch span.Type {
	case request.EventTypeHTTP, request.EventTypeHTTPClient:
		return is.HTTPEnabled()
	case request.EventTypeGRPC, request.EventTypeGRPCClient:
		return is.GRPCEnabled()
	case request.EventTypeSQLClient:
		return is.SQLEnabled()
	case request.EventTypeRedisClient, request.EventTypeRedisServer:
		return is.RedisEnabled()
	case request.EventTypeKafkaClient, request.EventTypeKafkaServer:
		return is.KafkaEnabled()
	case request.EventTypeMongoClient:
		return is.MongoEnabled()
	case request.EventTypeManualSpan:
		return true
	case request.EventTypeFailedConnect:
		return true
	}

	return false
}

// TODO use semconv.DBSystemRedis when we update to OTEL semantic conventions library 1.30
var (
	dbSystemRedis   = attribute.String(string(attr.DBSystemName), semconv.DBSystemRedis.Value.AsString())
	dbSystemMongo   = attribute.String(string(attr.DBSystemName), semconv.DBSystemMongoDB.Value.AsString())
	spanMetricsSkip = attribute.Bool(string(attr.SkipSpanMetrics), true)
)

//nolint:cyclop
func TraceAttributesSelector(span *request.Span, optionalAttrs map[attr.Name]struct{}) []attribute.KeyValue {
	var attrs []attribute.KeyValue

	switch span.Type {
	case request.EventTypeHTTP:
		attrs = []attribute.KeyValue{
			request.HTTPRequestMethod(span.Method),
			request.HTTPResponseStatusCode(span.Status),
			request.HTTPUrlPath(span.Path),
			request.ClientAddr(request.PeerAsClient(span)),
			request.ServerAddr(request.SpanHost(span)),
			request.ServerPort(span.HostPort),
			request.HTTPRequestBodySize(int(span.RequestBodyLength())),
			request.HTTPResponseBodySize(span.ResponseBodyLength()),
		}
		if span.Route != "" {
			attrs = append(attrs, semconv.HTTPRoute(span.Route))
		}
		if span.SubType == request.HTTPSubtypeGraphQL && span.GraphQL != nil {
			attrs = append(attrs, semconv.GraphqlDocument(span.GraphQL.Document))
			attrs = append(attrs, semconv.GraphqlOperationName(span.GraphQL.OperationName))
			attrs = append(attrs, request.GraphqlOperationType(span.GraphQL.OperationType))
		}
	case request.EventTypeGRPC:
		attrs = []attribute.KeyValue{
			semconv.RPCMethod(span.Path),
			semconv.RPCSystemGRPC,
			semconv.RPCGRPCStatusCodeKey.Int(span.Status),
			request.ClientAddr(request.PeerAsClient(span)),
			request.ServerAddr(request.SpanHost(span)),
			request.ServerPort(span.HostPort),
		}
	case request.EventTypeHTTPClient:
		host := request.HTTPClientHost(span)
		scheme := request.HTTPScheme(span)
		url := span.Path
		if span.HasOriginalHost() {
			url = request.URLFull(scheme, host, span.Path)
		}

		attrs = []attribute.KeyValue{
			request.HTTPRequestMethod(span.Method),
			request.HTTPResponseStatusCode(span.Status),
			request.HTTPUrlFull(url),
			semconv.HTTPScheme(scheme),
			request.ServerAddr(host),
			request.ServerPort(span.HostPort),
			request.HTTPRequestBodySize(int(span.RequestBodyLength())),
			request.HTTPResponseBodySize(span.ResponseBodyLength()),
		}

		if span.SubType == request.HTTPSubtypeElasticsearch && span.Elasticsearch != nil {
			attrs = append(attrs, request.DBCollectionName(span.Elasticsearch.DBCollectionName))
			attrs = append(attrs, request.ElasticsearchNodeName(span.Elasticsearch.NodeName))
			attrs = append(attrs, request.DBNamespace(span.DBNamespace))
			if _, ok := optionalAttrs[attr.DBQueryText]; ok {
				attrs = append(attrs, request.DBQueryText(span.Elasticsearch.DBQueryText))
			}
			attrs = append(attrs, request.DBOperationName(span.Elasticsearch.DBOperationName))
			attrs = append(attrs, request.DBSystemName(semconv.DBSystemElasticsearch.Value.AsString()))
			attrs = append(attrs, request.ErrorType(span.DBError.ErrorCode))
		}

		if span.SubType == request.HTTPSubtypeAWSS3 && span.AWS != nil {
			attrs = append(attrs, semconv.RPCService("S3"))
			attrs = append(attrs, request.RPCSystem("aws-api"))
			attrs = append(attrs, semconv.RPCMethod(span.AWS.S3.Method))
			attrs = append(attrs, semconv.CloudRegion(span.AWS.S3.Region))
			attrs = append(attrs, semconv.AWSRequestID(span.AWS.S3.RequestID))
			attrs = append(attrs, request.AWSExtendedRequestID(span.AWS.S3.ExtendedRequestID))
			attrs = append(attrs, semconv.AWSS3Bucket(span.AWS.S3.Bucket))
			attrs = append(attrs, semconv.AWSS3Key(span.AWS.S3.Key))
		}
	case request.EventTypeGRPCClient:
		attrs = []attribute.KeyValue{
			semconv.RPCMethod(span.Path),
			semconv.RPCSystemGRPC,
			semconv.RPCGRPCStatusCodeKey.Int(span.Status),
			request.ServerAddr(request.HostAsServer(span)),
			request.ServerPort(span.HostPort),
		}
	case request.EventTypeSQLClient:
		attrs = []attribute.KeyValue{
			request.ServerAddr(request.HostAsServer(span)),
			request.ServerPort(span.HostPort),
			span.DBSystemName(), // We can distinguish in the future for MySQL, Postgres etc
		}
		if _, ok := optionalAttrs[attr.DBQueryText]; ok {
			attrs = append(attrs, request.DBQueryText(span.Statement))
		}
		operation := span.Method
		if operation != "" {
			attrs = append(attrs, request.DBOperationName(operation))
			table := span.Path
			if table != "" {
				attrs = append(attrs, request.DBCollectionName(table))
			}
		}
		if span.Status == 1 && span.SQLError != nil {
			attrs = append(attrs, request.DBResponseStatusCode(strconv.Itoa(int(span.SQLError.Code))))
			attrs = append(attrs, request.ErrorType(span.SQLError.SQLState))
		}
	case request.EventTypeRedisServer, request.EventTypeRedisClient:
		attrs = []attribute.KeyValue{
			request.ServerAddr(request.HostAsServer(span)),
			request.ServerPort(span.HostPort),
			dbSystemRedis,
		}
		operation := span.Method
		if operation != "" {
			attrs = append(attrs, request.DBOperationName(operation))
			if _, ok := optionalAttrs[attr.DBQueryText]; ok {
				query := span.Path
				if query != "" {
					attrs = append(attrs, request.DBQueryText(query))
				}
			}
		}
		if span.Status == 1 {
			attrs = append(attrs, request.DBResponseStatusCode(span.DBError.ErrorCode))
		}
		if span.DBNamespace != "" {
			attrs = append(attrs, request.DBNamespace(span.DBNamespace))
		}
	case request.EventTypeKafkaServer, request.EventTypeKafkaClient:
		operation := request.MessagingOperationType(span.Method)
		attrs = []attribute.KeyValue{
			request.ServerAddr(request.HostAsServer(span)),
			request.ServerPort(span.HostPort),
			semconv.MessagingSystemKafka,
			semconv.MessagingDestinationName(span.Path),
			semconv.MessagingClientID(span.Statement),
			operation,
		}
		if span.MessagingInfo != nil {
			attrs = append(attrs, request.MessagingPartition(span.MessagingInfo.Partition))
			if span.Method == request.MessagingProcess {
				attrs = append(attrs, request.MessagingKafkaOffset(span.MessagingInfo.Offset))
			}
		}
	case request.EventTypeMongoClient:
		attrs = []attribute.KeyValue{
			request.ServerAddr(request.HostAsServer(span)),
			request.ServerPort(span.HostPort),
			dbSystemMongo,
		}
		operation := span.Method
		if operation != "" {
			attrs = append(attrs, request.DBOperationName(operation))
		}
		if span.Path != "" {
			attrs = append(attrs, request.DBCollectionName(span.Path))
		}
		if span.Status == 1 {
			attrs = append(attrs, request.DBResponseStatusCode(span.DBError.ErrorCode))
		}
		if span.DBNamespace != "" {
			attrs = append(attrs, request.DBNamespace(span.DBNamespace))
		}
	case request.EventTypeManualSpan:
		attrs = manualSpanAttributes(span)
	case request.EventTypeFailedConnect:
		attrs = []attribute.KeyValue{
			request.ClientAddr(request.PeerAsClient(span)),
			request.ServerAddr(request.SpanHost(span)),
			request.ServerPort(span.HostPort),
		}
	}

	if _, ok := optionalAttrs[attr.SkipSpanMetrics]; ok {
		attrs = append(attrs, spanMetricsSkip)
	}

	return attrs
}

func spanKind(span *request.Span) trace2.SpanKind {
	switch span.Type {
	case request.EventTypeHTTP, request.EventTypeGRPC, request.EventTypeRedisServer, request.EventTypeKafkaServer:
		return trace2.SpanKindServer
	case request.EventTypeHTTPClient, request.EventTypeGRPCClient, request.EventTypeSQLClient, request.EventTypeRedisClient, request.EventTypeMongoClient, request.EventTypeFailedConnect:
		return trace2.SpanKindClient
	case request.EventTypeKafkaClient:
		switch span.Method {
		case request.MessagingPublish:
			return trace2.SpanKindProducer
		case request.MessagingProcess:
			return trace2.SpanKindConsumer
		}
	}
	return trace2.SpanKindInternal
}

func spanStartTime(t request.Timings) time.Time {
	realStart := t.RequestStart
	if t.Start.Before(realStart) {
		realStart = t.Start
	}
	return realStart
}

func manualSpanAttributes(span *request.Span) []attribute.KeyValue {
	attrs := []attribute.KeyValue{}

	if span.Statement == "" {
		return attrs
	}

	var unmarshaledAttrs []SpanAttr
	err := json.Unmarshal([]byte(span.Statement), &unmarshaledAttrs)
	if err != nil {
		fmt.Println(err)
		return attrs
	}

	for i := range unmarshaledAttrs {
		akv := unmarshaledAttrs[i]
		key := unix.ByteSliceToString(akv.Key[:])
		switch akv.Vtype {
		case uint8(attribute.BOOL):
			attrs = append(attrs, attribute.Bool(key, akv.Value[0] != 0))
		case uint8(attribute.INT64):
			v := binary.LittleEndian.Uint64(akv.Value[:8])
			attrs = append(attrs, attribute.Int(key, int(v)))
		case uint8(attribute.FLOAT64):
			v := math.Float64frombits(binary.LittleEndian.Uint64(akv.Value[:8]))
			attrs = append(attrs, attribute.Float64(key, v))
		case uint8(attribute.STRING):
			attrs = append(attrs, attribute.String(key, unix.ByteSliceToString(akv.Value[:])))
		}
	}

	return attrs
}

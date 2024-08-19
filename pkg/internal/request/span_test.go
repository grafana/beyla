package request

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	trace2 "go.opentelemetry.io/otel/trace"
)

func TestSpanClientServer(t *testing.T) {
	for _, st := range []EventType{EventTypeHTTP, EventTypeGRPC} {
		span := &Span{
			Type: st,
		}
		assert.False(t, span.IsClientSpan())
	}

	for _, st := range []EventType{EventTypeHTTPClient, EventTypeGRPCClient, EventTypeSQLClient} {
		span := &Span{
			Type: st,
		}
		assert.True(t, span.IsClientSpan())
	}
}

func TestEventTypeString(t *testing.T) {
	typeStringMap := map[EventType]string{
		EventTypeHTTP:        "HTTP",
		EventTypeGRPC:        "GRPC",
		EventTypeHTTPClient:  "HTTPClient",
		EventTypeGRPCClient:  "GRPCClient",
		EventTypeSQLClient:   "SQLClient",
		EventTypeRedisClient: "RedisClient",
		EventTypeKafkaClient: "KafkaClient",
		EventTypeRedisServer: "RedisServer",
		EventTypeKafkaServer: "KafkaServer",
		EventType(99):        "UNKNOWN (99)",
	}

	for ev, str := range typeStringMap {
		assert.Equal(t, ev.String(), str)
	}
}

func TestIgnoreModeString(t *testing.T) {
	modeStringMap := map[ignoreMode]string{
		ignoreMetrics:                            "Metrics",
		ignoreTraces:                             "Traces",
		ignoreMode(0):                            "",
		ignoreMode(ignoreTraces | ignoreMetrics): "MetricsTraces",
	}

	for mode, str := range modeStringMap {
		assert.Equal(t, mode.String(), str)
	}
}

func TestKindString(t *testing.T) {
	m := map[*Span]string{
		&Span{Type: EventTypeHTTP}:                                  "SPAN_KIND_SERVER",
		&Span{Type: EventTypeGRPC}:                                  "SPAN_KIND_SERVER",
		&Span{Type: EventTypeKafkaServer}:                           "SPAN_KIND_SERVER",
		&Span{Type: EventTypeRedisServer}:                           "SPAN_KIND_SERVER",
		&Span{Type: EventTypeHTTPClient}:                            "SPAN_KIND_CLIENT",
		&Span{Type: EventTypeGRPCClient}:                            "SPAN_KIND_CLIENT",
		&Span{Type: EventTypeSQLClient}:                             "SPAN_KIND_CLIENT",
		&Span{Type: EventTypeRedisClient}:                           "SPAN_KIND_CLIENT",
		&Span{Type: EventTypeKafkaClient, Method: MessagingPublish}: "SPAN_KIND_PRODUCER",
		&Span{Type: EventTypeKafkaClient, Method: MessagingProcess}: "SPAN_KIND_CONSUMER",
		&Span{}: "SPAN_KIND_INTERNAL",
	}

	for span, str := range m {
		assert.Equal(t, span.ServiceGraphKind(), str)
	}
}

type jsonObject = map[string]interface{}

func deserializeJSONObject(data []byte) (jsonObject, error) {
	var object jsonObject
	err := json.Unmarshal(data, &object)

	return object, err
}

func TestSerializeJSONSpans(t *testing.T) {
	type testData struct {
		eventType EventType
		attribs   map[string]any
	}

	tData := []testData{
		testData{
			eventType: EventTypeHTTP,
			attribs: map[string]any{
				"method":     "method",
				"status":     "200",
				"url":        "path",
				"contentLen": "1024",
				"route":      "route",
				"clientAddr": "peername",
				"serverAddr": "hostname",
				"serverPort": "5678",
			},
		},
		testData{
			eventType: EventTypeHTTPClient,
			attribs: map[string]any{
				"method":     "method",
				"status":     "200",
				"url":        "path",
				"clientAddr": "peername",
				"serverAddr": "hostname",
				"serverPort": "5678",
			},
		},
		testData{
			eventType: EventTypeGRPC,
			attribs: map[string]any{
				"method":     "path",
				"status":     "200",
				"clientAddr": "peername",
				"serverAddr": "hostname",
				"serverPort": "5678",
			},
		},
		testData{
			eventType: EventTypeGRPCClient,
			attribs: map[string]any{
				"method":     "path",
				"status":     "200",
				"serverAddr": "hostname",
				"serverPort": "5678",
			},
		},
		testData{
			eventType: EventTypeSQLClient,
			attribs: map[string]any{
				"serverAddr": "hostname",
				"serverPort": "5678",
				"operation":  "method",
				"table":      "path",
				"statement":  "statement",
			},
		},
		testData{
			eventType: EventTypeRedisClient,
			attribs:   map[string]any{},
		},
		testData{
			eventType: EventTypeKafkaClient,
			attribs:   map[string]any{},
		},
		testData{
			eventType: EventTypeRedisServer,
			attribs: map[string]any{
				"serverAddr": "hostname",
				"serverPort": "5678",
				"operation":  "method",
				"statement":  "statement",
				"query":      "path",
			},
		},
		testData{
			eventType: EventTypeKafkaServer,
			attribs: map[string]any{
				"serverAddr": "hostname",
				"serverPort": "5678",
				"operation":  "method",
				"clientId":   "otherns",
			},
		},
	}

	test := func(t *testing.T, tData *testData) {
		span := Span{
			Type:           tData.eventType,
			IgnoreSpan:     ignoreMetrics,
			Method:         "method",
			Path:           "path",
			Route:          "route",
			Peer:           "peer",
			PeerPort:       1234,
			Host:           "host",
			HostPort:       5678,
			Status:         200,
			ContentLength:  1024,
			RequestStart:   10000,
			Start:          15000,
			End:            35000,
			TraceID:        trace2.TraceID{0x1, 0x2, 0x3},
			SpanID:         trace2.SpanID{0x1, 0x2, 0x3},
			ParentSpanID:   trace2.SpanID{0x1, 0x2, 0x3},
			Flags:          1,
			PeerName:       "peername",
			HostName:       "hostname",
			OtherNamespace: "otherns",
			Statement:      "statement",
		}

		data, err := json.MarshalIndent(span, "", " ")

		require.NoError(t, err)

		s, err := deserializeJSONObject(data)

		require.NoError(t, err)

		assert.Equal(t, map[string]any{
			"type":                tData.eventType.String(),
			"kind":                span.ServiceGraphKind(),
			"ignoreSpan":          "Metrics",
			"peer":                "peer",
			"peerPort":            "1234",
			"host":                "host",
			"hostPort":            "5678",
			"peerName":            "peername",
			"hostName":            "hostname",
			"start":               s["start"],
			"handlerStart":        s["handlerStart"],
			"end":                 s["end"],
			"duration":            "25µs",
			"durationUSec":        "25",
			"handlerDuration":     "20µs",
			"handlerDurationUSec": "20",
			"traceID":             "01020300000000000000000000000000",
			"spanID":              "0102030000000000",
			"parentSpanID":        "0102030000000000",
			"flags":               "1",
			"attributes":          tData.attribs,
		}, s)
	}

	for i := range tData {
		test(t, &tData[i])
	}
}

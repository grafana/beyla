package request

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	trace2 "go.opentelemetry.io/otel/trace"

	"github.com/grafana/beyla/v2/pkg/internal/svc"
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

func TestDetectsOTelExport(t *testing.T) {
	// Metrics
	tests := []struct {
		name    string
		span    Span
		exports bool
	}{
		{
			name:    "HTTP server spans don't export",
			span:    Span{Type: EventTypeHTTP, Method: "GET", Path: "/v1/metrics", RequestStart: 100, End: 200, Status: 200},
			exports: false,
		},
		{
			name:    "HTTP /foo doesn't export",
			span:    Span{Type: EventTypeHTTPClient, Method: "GET", Path: "/foo", RequestStart: 100, End: 200, Status: 200},
			exports: false,
		},
		{
			name:    "HTTP failed spans don't export",
			span:    Span{Type: EventTypeHTTPClient, Method: "GET", Path: "/v1/metrics", RequestStart: 100, End: 200, Status: 401},
			exports: false,
		},
		{
			name:    "Successful HTTP /v1/metrics spans export",
			span:    Span{Type: EventTypeHTTPClient, Method: "GET", Path: "/v1/metrics", RequestStart: 100, End: 200, Status: 200},
			exports: true,
		},
		{
			name:    "Successful HTTP /prefix/v1/metrics spans export",
			span:    Span{Type: EventTypeHTTPClient, Method: "GET", Path: "/prefix/v1/metrics", RequestStart: 100, End: 200, Status: 200},
			exports: true,
		},
		{
			name:    "GRPC server spans don't export",
			span:    Span{Type: EventTypeGRPC, Method: "GET", Path: "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export", RequestStart: 100, End: 200, Status: 0},
			exports: false,
		},
		{
			name:    "GRPC /v1/metrics doesn't export",
			span:    Span{Type: EventTypeGRPCClient, Method: "GET", Path: "/v1/metrics", RequestStart: 100, End: 200, Status: 0},
			exports: false,
		},
		{
			name:    "GRPC failed spans don't export",
			span:    Span{Type: EventTypeGRPCClient, Method: "GET", Path: "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export", RequestStart: 100, End: 200, Status: 1},
			exports: false,
		},
		{
			name:    "Successfull GRPC /v1/metrics spans export",
			span:    Span{Type: EventTypeGRPCClient, Method: "GET", Path: "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export", RequestStart: 100, End: 200, Status: 0},
			exports: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.exports, tt.span.IsExportMetricsSpan())
			assert.Equal(t, false, tt.span.IsExportTracesSpan())
		})
	}

	// Traces
	tests = []struct {
		name    string
		span    Span
		exports bool
	}{
		{
			name:    "HTTP server spans don't export",
			span:    Span{Type: EventTypeHTTP, Method: "GET", Path: "/v1/traces", RequestStart: 100, End: 200, Status: 200},
			exports: false,
		},
		{
			name:    "/foo doesn't export",
			span:    Span{Type: EventTypeHTTPClient, Method: "GET", Path: "/foo", RequestStart: 100, End: 200, Status: 200},
			exports: false,
		},
		{
			name:    "HTTP failed spans don't export",
			span:    Span{Type: EventTypeHTTPClient, Method: "GET", Path: "/v1/traces", RequestStart: 100, End: 200, Status: 401},
			exports: false,
		},
		{
			name:    "Successfull HTTP /v1/traces spans export",
			span:    Span{Type: EventTypeHTTPClient, Method: "GET", Path: "/v1/traces", RequestStart: 100, End: 200, Status: 200},
			exports: true,
		},
		{
			name:    "GRPC server spans don't export",
			span:    Span{Type: EventTypeGRPC, Method: "GET", Path: "/opentelemetry.proto.collector.trace.v1.TraceService/Export", RequestStart: 100, End: 200, Status: 0},
			exports: false,
		},
		{
			name:    "GRPC /v1/traces doesn't export",
			span:    Span{Type: EventTypeGRPCClient, Method: "GET", Path: "/v1/traces", RequestStart: 100, End: 200, Status: 0},
			exports: false,
		},
		{
			name:    "GRPC failed spans don't export",
			span:    Span{Type: EventTypeGRPCClient, Method: "GET", Path: "/opentelemetry.proto.collector.trace.v1.TraceService/Export", RequestStart: 100, End: 200, Status: 1},
			exports: false,
		},
		{
			name:    "Successfull GRPC /v1/traces spans export",
			span:    Span{Type: EventTypeGRPCClient, Method: "GET", Path: "/opentelemetry.proto.collector.trace.v1.TraceService/Export", RequestStart: 100, End: 200, Status: 0},
			exports: true,
		}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.exports, tt.span.IsExportTracesSpan())
			assert.Equal(t, false, tt.span.IsExportMetricsSpan())
		})
	}
}

func TestSelfReferencingSpan(t *testing.T) {
	// Metrics
	tests := []struct {
		name    string
		span    Span
		selfref bool
	}{
		{
			name:    "Not a self-reference",
			span:    Span{Type: EventTypeHTTP, Method: "GET", Path: "/v1/metrics", RequestStart: 100, End: 200, Status: 200, Host: "10.10.10.10", Peer: "10.11.10.11", OtherNamespace: "", Service: svc.Attrs{UID: svc.UID{Namespace: ""}}},
			selfref: false,
		},
		{
			name:    "Not a self-reference, same IP, different namespace",
			span:    Span{Type: EventTypeHTTP, Method: "GET", Path: "/v1/metrics", RequestStart: 100, End: 200, Status: 200, Host: "10.10.10.10", Peer: "10.10.10.10", OtherNamespace: "B", Service: svc.Attrs{UID: svc.UID{Namespace: "A"}}},
			selfref: false,
		},
		{
			name:    "Same IP different namespace, but the other namespace is empty",
			span:    Span{Type: EventTypeHTTP, Method: "GET", Path: "/v1/metrics", RequestStart: 100, End: 200, Status: 200, Host: "10.10.10.10", Peer: "10.10.10.10", OtherNamespace: "", Service: svc.Attrs{UID: svc.UID{Namespace: "A"}}},
			selfref: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.selfref, tt.span.IsSelfReferenceSpan())
		})
	}
}

func TestHostPeerClientServer(t *testing.T) {
	// Metrics
	tests := []struct {
		name   string
		span   Span
		client string
		server string
	}{
		{
			name:   "Same namespaces HTTP",
			span:   Span{Type: EventTypeHTTP, PeerName: "client", HostName: "server", OtherNamespace: "same", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server",
		},
		{
			name:   "Client in different namespace",
			span:   Span{Type: EventTypeHTTP, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client.far",
			server: "server",
		},
		{
			name:   "Client in different namespace",
			span:   Span{Type: EventTypeHTTP, Peer: "1.1.1.1", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "1.1.1.1",
			server: "server",
		},
		{
			name:   "Same namespaces for HTTP client",
			span:   Span{Type: EventTypeHTTPClient, PeerName: "client", HostName: "server", OtherNamespace: "same", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server",
		},
		{
			name:   "Server in different namespace ",
			span:   Span{Type: EventTypeHTTPClient, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server.far",
		},
		{
			name:   "Server in different namespace ",
			span:   Span{Type: EventTypeHTTPClient, PeerName: "client", Host: "2.2.2.2", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "2.2.2.2",
		},
		{
			name:   "Same namespaces GRPC",
			span:   Span{Type: EventTypeGRPC, PeerName: "client", HostName: "server", OtherNamespace: "same", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server",
		},
		{
			name:   "Client in different namespace GRPC",
			span:   Span{Type: EventTypeGRPC, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client.far",
			server: "server",
		},
		{
			name:   "Same namespaces for GRPC client",
			span:   Span{Type: EventTypeGRPCClient, PeerName: "client", HostName: "server", OtherNamespace: "same", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server",
		},
		{
			name:   "Server in different namespace GRPC",
			span:   Span{Type: EventTypeGRPCClient, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server.far",
		},
		{
			name:   "Same namespaces for SQL client",
			span:   Span{Type: EventTypeSQLClient, PeerName: "client", HostName: "server", OtherNamespace: "same", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server",
		},
		{
			name:   "Server in different namespace SQL",
			span:   Span{Type: EventTypeSQLClient, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server.far",
		},
		{
			name:   "Same namespaces for Redis client",
			span:   Span{Type: EventTypeRedisClient, PeerName: "client", HostName: "server", OtherNamespace: "same", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server",
		},
		{
			name:   "Server in different namespace Redis",
			span:   Span{Type: EventTypeRedisClient, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server.far",
		},
		{
			name:   "Client in different namespace Redis",
			span:   Span{Type: EventTypeRedisServer, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client.far",
			server: "server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.client, PeerAsClient(&tt.span))
			assert.Equal(t, tt.server, HostAsServer(&tt.span))
		})
	}
}

package pipe

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mariomac/pipes/pkg/graph"
	"github.com/mariomac/pipes/pkg/node"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"

	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
	"github.com/grafana/beyla/pkg/internal/testutil"
	"github.com/grafana/beyla/pkg/internal/traces"
	"github.com/grafana/beyla/pkg/internal/transform"
	"github.com/grafana/beyla/test/collector"
)

const testTimeout = 5 * time.Second

func gctx() *global.ContextInfo {
	return &global.ContextInfo{
		Metrics: imetrics.NoopReporter{},
	}
}

func TestBasicPipeline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tc, err := collector.Start(ctx)
	require.NoError(t, err)

	gb := newGraphBuilder(ctx, &Config{
		Metrics: otel.MetricsConfig{
			MetricsEndpoint: tc.ServerEndpoint, ReportTarget: true,
			ReportPeerInfo: true, Interval: 10 * time.Millisecond,
			ReportersCacheLen: 16,
		},
	}, gctx(), make(<-chan []request.Span))
	// Override eBPF tracer to send some fake data
	graph.RegisterStart(gb.builder, func(_ traces.ReadDecorator) (node.StartFunc[[]request.Span], error) {
		return func(out chan<- []request.Span) {
			out <- newRequest("foo-svc", 1, "GET", "/foo/bar", "1.1.1.1:3456", 404)
			// closing prematurely the input node would finish the whole graph processing
			// and OTEL exporters could be closed, so we wait.
			time.Sleep(testTimeout)
		}, nil
	})
	pipe, err := gb.buildGraph()
	require.NoError(t, err)

	go pipe.Run(ctx)

	event := testutil.ReadChannel(t, tc.Records, testTimeout)
	assert.Equal(t, collector.MetricRecord{
		Name: "http.server.duration",
		Unit: "s",
		Attributes: map[string]string{
			string(otel.HTTPRequestMethodKey):      "GET",
			string(otel.HTTPResponseStatusCodeKey): "404",
			string(otel.HTTPUrlPathKey):            "/foo/bar",
			string(otel.ClientAddrKey):             "1.1.1.1",
			string(semconv.ServiceNameKey):         "foo-svc",
		},
		Type: pmetric.MetricTypeHistogram,
	}, event)

}

func TestTracerPipeline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tc, err := collector.Start(ctx)
	require.NoError(t, err)

	gb := newGraphBuilder(ctx, &Config{
		Traces: otel.TracesConfig{
			BatchTimeout:      10 * time.Millisecond,
			TracesEndpoint:    tc.ServerEndpoint,
			ReportersCacheLen: 16,
		},
	}, gctx(), make(<-chan []request.Span))
	// Override eBPF tracer to send some fake data
	graph.RegisterStart(gb.builder, func(_ traces.ReadDecorator) (node.StartFunc[[]request.Span], error) {
		return func(out chan<- []request.Span) {
			out <- newRequest("bar-svc", 1, "GET", "/foo/bar", "1.1.1.1:3456", 404)
			// closing prematurely the input node would finish the whole graph processing
			// and OTEL exporters could be closed, so we wait.
			time.Sleep(testTimeout)
		}, nil
	})
	pipe, err := gb.buildGraph()
	require.NoError(t, err)

	go pipe.Run(ctx)

	event := testutil.ReadChannel(t, tc.TraceRecords, testTimeout)
	matchInnerTraceEvent(t, "in queue", event)
	event = testutil.ReadChannel(t, tc.TraceRecords, testTimeout)
	matchInnerTraceEvent(t, "processing", event)
	event = testutil.ReadChannel(t, tc.TraceRecords, testTimeout)
	matchTraceEvent(t, "GET", event)
}

func TestTracerPipelineBadTimestamps(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tc, err := collector.Start(ctx)
	require.NoError(t, err)

	gb := newGraphBuilder(ctx, &Config{
		Traces: otel.TracesConfig{
			BatchTimeout:      10 * time.Millisecond,
			TracesEndpoint:    tc.ServerEndpoint,
			ReportersCacheLen: 16,
		},
	}, gctx(), make(<-chan []request.Span))
	// Override eBPF tracer to send some fake data
	graph.RegisterStart(gb.builder, func(_ traces.ReadDecorator) (node.StartFunc[[]request.Span], error) {
		return func(out chan<- []request.Span) {
			out <- newRequestWithTiming("svc1", 1, request.EventTypeHTTP, "GET", "/attach", "2.2.2.2:1234", 200, 60000, 59999, 70000)
			// closing prematurely the input node would finish the whole graph processing
			// and OTEL exporters could be closed, so we wait.
			time.Sleep(testTimeout)
		}, nil
	})
	pipe, err := gb.buildGraph()
	require.NoError(t, err)

	go pipe.Run(ctx)

	event := testutil.ReadChannel(t, tc.TraceRecords, testTimeout)
	matchNestedEvent(t, "GET", "GET", "/attach", "200", ptrace.SpanKindServer, event)
}

func TestRouteConsolidation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tc, err := collector.Start(ctx)
	require.NoError(t, err)

	gb := newGraphBuilder(ctx, &Config{
		Metrics: otel.MetricsConfig{
			ReportPeerInfo:  false, // no peer info
			MetricsEndpoint: tc.ServerEndpoint, Interval: 10 * time.Millisecond,
			ReportersCacheLen: 16,
		},
		Routes: &transform.RoutesConfig{Patterns: []string{"/user/{id}", "/products/{id}/push"}},
	}, gctx(), make(<-chan []request.Span))
	// Override eBPF tracer to send some fake data
	graph.RegisterStart(gb.builder, func(_ traces.ReadDecorator) (node.StartFunc[[]request.Span], error) {
		return func(out chan<- []request.Span) {
			out <- newRequest("svc-1", 1, "GET", "/user/1234", "1.1.1.1:3456", 200)
			out <- newRequest("svc-1", 2, "GET", "/products/3210/push", "1.1.1.1:3456", 200)
			out <- newRequest("svc-1", 3, "GET", "/attach", "1.1.1.1:3456", 200)
			// closing prematurely the input node would finish the whole graph processing
			// and OTEL exporters could be closed, so we wait.
			time.Sleep(testTimeout)
		}, nil
	})
	pipe, err := gb.buildGraph()
	require.NoError(t, err)

	go pipe.Run(ctx)

	// expect to receive 3 events without any guaranteed order
	events := map[string]collector.MetricRecord{}
	for i := 0; i < 3; i++ {
		ev := testutil.ReadChannel(t, tc.Records, testTimeout)
		events[ev.Attributes[string(semconv.HTTPRouteKey)]] = ev
	}

	assert.Equal(t, collector.MetricRecord{
		Name: "http.server.duration",
		Unit: "s",
		Attributes: map[string]string{
			string(semconv.ServiceNameKey):         "svc-1",
			string(otel.HTTPRequestMethodKey):      "GET",
			string(otel.HTTPResponseStatusCodeKey): "200",
			string(semconv.HTTPRouteKey):           "/user/{id}",
		},
		Type: pmetric.MetricTypeHistogram,
	}, events["/user/{id}"])

	assert.Equal(t, collector.MetricRecord{
		Name: "http.server.duration",
		Unit: "s",
		Attributes: map[string]string{
			string(semconv.ServiceNameKey):         "svc-1",
			string(otel.HTTPRequestMethodKey):      "GET",
			string(otel.HTTPResponseStatusCodeKey): "200",
			string(semconv.HTTPRouteKey):           "/products/{id}/push",
		},
		Type: pmetric.MetricTypeHistogram,
	}, events["/products/{id}/push"])

	assert.Equal(t, collector.MetricRecord{
		Name: "http.server.duration",
		Unit: "s",
		Attributes: map[string]string{
			string(semconv.ServiceNameKey):         "svc-1",
			string(otel.HTTPRequestMethodKey):      "GET",
			string(otel.HTTPResponseStatusCodeKey): "200",
			string(semconv.HTTPRouteKey):           "/**",
		},
		Type: pmetric.MetricTypeHistogram,
	}, events["/**"])
}

func TestGRPCPipeline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tc, err := collector.Start(ctx)
	require.NoError(t, err)

	gb := newGraphBuilder(ctx, &Config{
		Metrics: otel.MetricsConfig{
			MetricsEndpoint: tc.ServerEndpoint, ReportTarget: true, ReportPeerInfo: true, Interval: time.Millisecond,
			ReportersCacheLen: 16,
		},
	}, gctx(), make(<-chan []request.Span))
	// Override eBPF tracer to send some fake data
	graph.RegisterStart(gb.builder, func(_ traces.ReadDecorator) (node.StartFunc[[]request.Span], error) {
		return func(out chan<- []request.Span) {
			out <- newGRPCRequest("grpc-svc", 1, "/foo/bar", 3)
			// closing prematurely the input node would finish the whole graph processing
			// and OTEL exporters could be closed, so we wait.
			time.Sleep(testTimeout)
		}, nil
	})
	pipe, err := gb.buildGraph()
	require.NoError(t, err)

	go pipe.Run(ctx)

	event := testutil.ReadChannel(t, tc.Records, testTimeout)
	assert.Equal(t, collector.MetricRecord{
		Name: "rpc.server.duration",
		Unit: "s",
		Attributes: map[string]string{
			string(semconv.ServiceNameKey):       "grpc-svc",
			string(semconv.RPCSystemKey):         "grpc",
			string(semconv.RPCGRPCStatusCodeKey): "3",
			string(semconv.RPCMethodKey):         "/foo/bar",
			string(otel.ClientAddrKey):           "1.1.1.1",
		},
		Type: pmetric.MetricTypeHistogram,
	}, event)
}

func TestTraceGRPCPipeline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tc, err := collector.Start(ctx)
	require.NoError(t, err)

	gb := newGraphBuilder(ctx, &Config{
		Traces: otel.TracesConfig{
			TracesEndpoint: tc.ServerEndpoint,
			BatchTimeout:   time.Millisecond, ReportersCacheLen: 16,
		},
	}, gctx(), make(<-chan []request.Span))
	// Override eBPF tracer to send some fake data
	graph.RegisterStart(gb.builder, func(_ traces.ReadDecorator) (node.StartFunc[[]request.Span], error) {
		return func(out chan<- []request.Span) {
			out <- newGRPCRequest("svc", 1, "foo.bar", 3)
			// closing prematurely the input node would finish the whole graph processing
			// and OTEL exporters could be closed, so we wait.
			time.Sleep(testTimeout)
		}, nil
	})
	pipe, err := gb.buildGraph()
	require.NoError(t, err)

	go pipe.Run(ctx)

	event := testutil.ReadChannel(t, tc.TraceRecords, testTimeout)
	matchInnerGRPCTraceEvent(t, "in queue", event)
	event = testutil.ReadChannel(t, tc.TraceRecords, testTimeout)
	matchInnerGRPCTraceEvent(t, "processing", event)
	event = testutil.ReadChannel(t, tc.TraceRecords, testTimeout)
	matchGRPCTraceEvent(t, "foo.bar", event)
}

func TestNestedSpanMatching(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tc, err := collector.Start(ctx)
	require.NoError(t, err)

	gb := newGraphBuilder(ctx, &Config{
		Traces: otel.TracesConfig{TracesEndpoint: tc.ServerEndpoint, ReportersCacheLen: 16},
	}, gctx(), make(<-chan []request.Span))
	// Override eBPF tracer to send some fake data with nested client span
	graph.RegisterStart(gb.builder, func(_ traces.ReadDecorator) (node.StartFunc[[]request.Span], error) {
		return func(out chan<- []request.Span) {
			out <- newRequestWithTiming("svc1", 1, request.EventTypeHTTPClient, "GET", "/attach", "2.2.2.2:1234", 200, 60000, 60000, 70000)
			out <- newRequestWithTiming("svc1", 1, request.EventTypeHTTP, "GET", "/user/1234", "1.1.1.1:3456", 200, 10000, 10000, 50000)
			out <- newRequestWithTiming("svc1", 3, request.EventTypeHTTPClient, "GET", "/products/3210/pull", "2.2.2.2:3456", 204, 80000, 80000, 90000)
			out <- newRequestWithTiming("svc1", 3, request.EventTypeHTTPClient, "GET", "/products/3211/pull", "2.2.2.2:3456", 203, 80000, 80000, 90000)
			out <- newRequestWithTiming("svc1", 2, request.EventTypeHTTP, "GET", "/products/3210/push", "1.1.1.1:3456", 200, 10000, 20000, 50000)
			out <- newRequestWithTiming("svc1", 3, request.EventTypeHTTP, "GET", "/attach", "1.1.1.1:3456", 200, 70000, 80000, 100000)
			out <- newRequestWithTiming("svc1", 1, request.EventTypeHTTPClient, "GET", "/attach2", "2.2.2.2:1234", 200, 30000, 30000, 40000)
			out <- newRequestWithTiming("svc1", 0, request.EventTypeHTTPClient, "GET", "/attach1", "2.2.2.2:1234", 200, 20000, 20000, 40000)
			out <- newRequestWithTiming("svc1", 1, request.EventTypeHTTP, "GET", "/user/3456", "1.1.1.1:3456", 200, 56000, 56000, 80000)
		}, nil
	})
	pipe, err := gb.buildGraph()
	require.NoError(t, err)

	go pipe.Run(ctx)

	// 1. The first event has no internal spans, goroutine Start and Start are the same
	event := testutil.ReadChannel(t, tc.TraceRecords, testTimeout)
	parent1ID := event.Attributes["span_id"]
	matchNestedEvent(t, "GET", "GET", "/user/1234", "200", ptrace.SpanKindServer, event)
	// 2. The second event is server "/products/3210/push", since the client span has a parent which hasn't arrived yet.
	// This event has nested server spans.
	event = testutil.ReadChannel(t, tc.TraceRecords, testTimeout)
	pIDQ := event.Attributes["parent_span_id"]
	matchNestedEvent(t, "in queue", "", "", "", ptrace.SpanKindInternal, event)
	event = testutil.ReadChannel(t, tc.TraceRecords, testTimeout)
	pIDP := event.Attributes["parent_span_id"]
	matchNestedEvent(t, "processing", "", "", "", ptrace.SpanKindInternal, event)
	event = testutil.ReadChannel(t, tc.TraceRecords, testTimeout)
	matchNestedEvent(t, "GET", "GET", "/products/3210/push", "200", ptrace.SpanKindServer, event)
	assert.Equal(t, pIDP, event.Attributes["span_id"])
	assert.Equal(t, pIDQ, event.Attributes["span_id"])
	// 3. Third event has client span as well, which we recorded just after we processed the first event
	event = testutil.ReadChannel(t, tc.TraceRecords, testTimeout)
	matchNestedEvent(t, "in queue", "", "", "", ptrace.SpanKindInternal, event)
	event = testutil.ReadChannel(t, tc.TraceRecords, testTimeout)
	spanID := event.Attributes["span_id"]
	parentID := event.Attributes["parent_span_id"]
	matchNestedEvent(t, "processing", "", "", "", ptrace.SpanKindInternal, event)
	event = testutil.ReadChannel(t, tc.TraceRecords, testTimeout)
	matchNestedEvent(t, "GET", "GET", "/attach", "200", ptrace.SpanKindServer, event)
	// the processing span is a child of the session span
	assert.Equal(t, parentID, event.Attributes["span_id"])
	// 4. The first client span id will be a child of the processing span, of the request with ID=3
	event = testutil.ReadChannel(t, tc.TraceRecords, testTimeout)
	matchNestedEvent(t, "GET", "GET", "/products/3210/pull", "204", ptrace.SpanKindClient, event)
	assert.Equal(t, spanID, event.Attributes["parent_span_id"])
	// Test that we correctly keep the list of all prior client events
	event = testutil.ReadChannel(t, tc.TraceRecords, testTimeout)
	matchNestedEvent(t, "GET", "GET", "/products/3211/pull", "203", ptrace.SpanKindClient, event)
	assert.Equal(t, spanID, event.Attributes["parent_span_id"])
	// 5. Next we should see a child span from the request with ID=1
	event = testutil.ReadChannel(t, tc.TraceRecords, testTimeout)
	matchNestedEvent(t, "GET", "GET", "/attach2", "200", ptrace.SpanKindClient, event)
	assert.Equal(t, parent1ID, event.Attributes["parent_span_id"])
	// 6. Now we see a client call without a parent span ID = 0
	event = testutil.ReadChannel(t, tc.TraceRecords, testTimeout)
	matchNestedEvent(t, "GET", "GET", "/attach1", "200", ptrace.SpanKindClient, event)
	assert.Equal(t, "", event.Attributes["parent_span_id"])
	// 7. Next we should see a server span with child span from the request with ID=1, this is the later server span with the same ID. We would preserve the span
	event = testutil.ReadChannel(t, tc.TraceRecords, testTimeout)
	parent1ID = event.Attributes["span_id"]
	matchNestedEvent(t, "GET", "GET", "/user/3456", "200", ptrace.SpanKindServer, event)
	event = testutil.ReadChannel(t, tc.TraceRecords, testTimeout)
	matchNestedEvent(t, "GET", "GET", "/attach", "200", ptrace.SpanKindClient, event)
	assert.Equal(t, parent1ID, event.Attributes["parent_span_id"])
}

func newRequest(serviceName string, id uint64, method, path, peer string, status int) []request.Span {
	return []request.Span{{
		Path:         path,
		Method:       method,
		Peer:         strings.Split(peer, ":")[0],
		Host:         getHostname(),
		HostPort:     8080,
		Status:       status,
		Type:         request.EventTypeHTTP,
		ID:           id,
		Start:        2,
		RequestStart: 1,
		End:          3,
		ServiceID:    svc.ID{Name: serviceName},
	}}
}

func newRequestWithTiming(svcName string, id uint64, kind request.EventType, method, path, peer string, status int, goStart, start, end uint64) []request.Span {
	return []request.Span{{
		Path:         path,
		Method:       method,
		Peer:         strings.Split(peer, ":")[0],
		Host:         getHostname(),
		HostPort:     8080,
		Type:         kind,
		Status:       status,
		ID:           id,
		RequestStart: int64(goStart),
		Start:        int64(start),
		End:          int64(end),
		ServiceID:    svc.ID{Name: svcName},
	}}
}

func newGRPCRequest(svcName string, id uint64, path string, status int) []request.Span {
	return []request.Span{{
		Path:         path,
		Peer:         "1.1.1.1",
		Host:         "127.0.0.1",
		HostPort:     8080,
		Status:       status,
		Type:         request.EventTypeGRPC,
		ID:           id,
		Start:        2,
		RequestStart: 1,
		End:          3,
		ServiceID:    svc.ID{Name: svcName},
	}}
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return ""
	}
	return hostname
}

func matchTraceEvent(t require.TestingT, name string, event collector.TraceRecord) {
	assert.Equal(t, collector.TraceRecord{
		Name: name,
		Attributes: map[string]string{
			string(otel.HTTPRequestMethodKey):      "GET",
			string(otel.HTTPResponseStatusCodeKey): "404",
			string(otel.HTTPUrlPathKey):            "/foo/bar",
			string(otel.ClientAddrKey):             "1.1.1.1",
			string(otel.ServerAddrKey):             getHostname(),
			string(otel.ServerPortKey):             "8080",
			string(otel.HTTPRequestBodySizeKey):    "0",
			"span_id":                              event.Attributes["span_id"],
			"parent_span_id":                       event.Attributes["parent_span_id"],
		},
		Kind: ptrace.SpanKindServer,
	}, event)
}

func matchInnerTraceEvent(t require.TestingT, name string, event collector.TraceRecord) {
	assert.Equal(t, collector.TraceRecord{
		Name: name,
		Attributes: map[string]string{
			"span_id":        event.Attributes["span_id"],
			"parent_span_id": event.Attributes["parent_span_id"],
		},
		Kind: ptrace.SpanKindInternal,
	}, event)
}

func matchGRPCTraceEvent(t *testing.T, name string, event collector.TraceRecord) {
	assert.Equal(t, collector.TraceRecord{
		Name: name,
		Attributes: map[string]string{
			string(semconv.RPCSystemKey):         "grpc",
			string(semconv.RPCGRPCStatusCodeKey): "3",
			string(semconv.RPCMethodKey):         "foo.bar",
			string(otel.ClientAddrKey):           "1.1.1.1",
			string(otel.ServerAddrKey):           "127.0.0.1",
			string(otel.ServerPortKey):           "8080",
			"span_id":                            event.Attributes["span_id"],
			"parent_span_id":                     event.Attributes["parent_span_id"],
		},
		Kind: ptrace.SpanKindServer,
	}, event)
}

func matchInnerGRPCTraceEvent(t *testing.T, name string, event collector.TraceRecord) {
	assert.Equal(t, collector.TraceRecord{
		Name: name,
		Attributes: map[string]string{
			"span_id":        event.Attributes["span_id"],
			"parent_span_id": event.Attributes["parent_span_id"],
		},
		Kind: ptrace.SpanKindInternal,
	}, event)
}

func matchNestedEvent(t *testing.T, name, method, target, status string, kind ptrace.SpanKind, event collector.TraceRecord) {
	assert.Equal(t, name, event.Name)
	assert.Equal(t, method, event.Attributes[string(otel.HTTPRequestMethodKey)])
	assert.Equal(t, status, event.Attributes[string(otel.HTTPResponseStatusCodeKey)])
	if kind == ptrace.SpanKindClient {
		assert.Equal(t, target, event.Attributes[string(otel.HTTPUrlFullKey)])
	} else {
		assert.Equal(t, target, event.Attributes[string(otel.HTTPUrlPathKey)])
	}
	assert.Equal(t, kind, event.Kind)
}

func newHTTPInfo(method, path, peer string, status int) []request.Span {
	return []request.Span{{
		Type:         1,
		Method:       method,
		Peer:         peer,
		Path:         path,
		Host:         getHostname(),
		HostPort:     8080,
		Status:       status,
		Start:        2,
		RequestStart: 2,
		End:          3,
		ServiceID:    svc.ID{Name: "comm"},
	}}
}

func matchInfoEvent(t *testing.T, name string, event collector.TraceRecord) {
	assert.Equal(t, collector.TraceRecord{
		Name: name,
		Attributes: map[string]string{
			string(otel.HTTPRequestMethodKey):      "PATCH",
			string(otel.HTTPResponseStatusCodeKey): "204",
			string(otel.HTTPUrlPathKey):            "/aaa/bbb",
			string(otel.ClientAddrKey):             "1.1.1.1",
			string(otel.ServerAddrKey):             getHostname(),
			string(otel.ServerPortKey):             "8080",
			string(otel.HTTPRequestBodySizeKey):    "0",
			"span_id":                              event.Attributes["span_id"],
			"parent_span_id":                       "",
		},
		Kind: ptrace.SpanKindServer,
	}, event)
}

func TestBasicPipelineInfo(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tc, err := collector.Start(ctx)
	require.NoError(t, err)

	tracesInput := make(chan []request.Span, 10)
	gb := newGraphBuilder(ctx, &Config{
		Metrics: otel.MetricsConfig{
			MetricsEndpoint: tc.ServerEndpoint, ReportTarget: true, ReportPeerInfo: true,
			Interval: 10 * time.Millisecond, ReportersCacheLen: 16,
		},
	}, gctx(), tracesInput)
	// send some fake data through the traces' input
	tracesInput <- newHTTPInfo("PATCH", "/aaa/bbb", "1.1.1.1", 204)
	pipe, err := gb.buildGraph()
	require.NoError(t, err)

	go pipe.Run(ctx)

	event := testutil.ReadChannel(t, tc.Records, testTimeout)
	assert.Equal(t, collector.MetricRecord{
		Name: "http.server.duration",
		Unit: "s",
		Attributes: map[string]string{
			string(otel.HTTPRequestMethodKey):      "PATCH",
			string(otel.HTTPResponseStatusCodeKey): "204",
			string(otel.HTTPUrlPathKey):            "/aaa/bbb",
			string(otel.ClientAddrKey):             "1.1.1.1",
			string(semconv.ServiceNameKey):         "comm",
		},
		Type: pmetric.MetricTypeHistogram,
	}, event)
}

func TestTracerPipelineInfo(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tc, err := collector.Start(ctx)
	require.NoError(t, err)

	gb := newGraphBuilder(ctx, &Config{
		Traces: otel.TracesConfig{TracesEndpoint: tc.ServerEndpoint, ReportersCacheLen: 16},
	}, gctx(), make(<-chan []request.Span))
	// Override eBPF tracer to send some fake data
	graph.RegisterStart(gb.builder, func(_ traces.ReadDecorator) (node.StartFunc[[]request.Span], error) {
		return func(out chan<- []request.Span) {
			out <- newHTTPInfo("PATCH", "/aaa/bbb", "1.1.1.1", 204)
		}, nil
	})
	pipe, err := gb.buildGraph()
	require.NoError(t, err)

	go pipe.Run(ctx)

	event := testutil.ReadChannel(t, tc.TraceRecords, testTimeout)
	matchInfoEvent(t, "PATCH", event)
}

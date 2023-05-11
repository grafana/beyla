package pipe

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/grafana/ebpf-autoinstrument/pkg/testutil"

	"github.com/mariomac/pipes/pkg/graph"
	"github.com/mariomac/pipes/pkg/node"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"

	ebpfcommon "github.com/grafana/ebpf-autoinstrument/pkg/ebpf/common"
	"github.com/grafana/ebpf-autoinstrument/pkg/export/otel"
	"github.com/grafana/ebpf-autoinstrument/pkg/transform"
	"github.com/grafana/ebpf-autoinstrument/test/collector"
)

const testTimeout = 500 * time.Second

func TestBasicPipeline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tc, err := collector.Start(ctx)
	require.NoError(t, err)

	gb := newGraphBuilder(&Config{Metrics: otel.MetricsConfig{MetricsEndpoint: tc.ServerEndpoint, ReportTarget: true, ReportPeerInfo: true}})
	// Override eBPF tracer to send some fake data
	graph.RegisterStart(gb.builder, func(_ context.Context, _ ebpfcommon.TracerConfig) (node.StartFuncCtx[[]ebpfcommon.HTTPRequestTrace], error) {
		return func(_ context.Context, out chan<- []ebpfcommon.HTTPRequestTrace) {
			out <- newRequest(1, "GET", "/foo/bar", "1.1.1.1:3456", 404)
		}, nil
	})
	pipe, err := gb.buildGraph(ctx)
	require.NoError(t, err)

	go pipe.Run(ctx)

	event := testutil.ReadChannel(t, tc.Records, testTimeout)
	assert.Equal(t, collector.MetricRecord{
		Name: "http.server.duration",
		Unit: "s",
		Attributes: map[string]string{
			string(semconv.HTTPMethodKey):      "GET",
			string(semconv.HTTPStatusCodeKey):  "404",
			string(semconv.HTTPTargetKey):      "/foo/bar",
			string(semconv.NetSockPeerAddrKey): "1.1.1.1",
		},
		Type: pmetric.MetricTypeHistogram,
	}, event)
}

func TestTracerPipeline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tc, err := collector.Start(ctx)
	require.NoError(t, err)

	gb := newGraphBuilder(&Config{Traces: otel.TracesConfig{TracesEndpoint: tc.ServerEndpoint, ServiceName: "test"}})
	// Override eBPF tracer to send some fake data
	graph.RegisterStart(gb.builder, func(_ context.Context, _ ebpfcommon.TracerConfig) (node.StartFuncCtx[[]ebpfcommon.HTTPRequestTrace], error) {
		return func(_ context.Context, out chan<- []ebpfcommon.HTTPRequestTrace) {
			out <- newRequest(1, "GET", "/foo/bar", "1.1.1.1:3456", 404)
		}, nil
	})
	pipe, err := gb.buildGraph(ctx)
	require.NoError(t, err)

	go pipe.Run(ctx)

	event := testutil.ReadChannel(t, tc.TraceRecords, testTimeout)
	matchInnerTraceEvent(t, "in queue", event)
	event = testutil.ReadChannel(t, tc.TraceRecords, testTimeout)
	matchInnerTraceEvent(t, "processing", event)
	event = testutil.ReadChannel(t, tc.TraceRecords, testTimeout)
	matchTraceEvent(t, "GET", event)
}

func TestRouteConsolidation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tc, err := collector.Start(ctx)
	require.NoError(t, err)

	gb := newGraphBuilder(&Config{
		Metrics: otel.MetricsConfig{MetricsEndpoint: tc.ServerEndpoint}, // ReportPeerInfo = false, no peer info
		Routes:  &transform.RoutesConfig{Patterns: []string{"/user/{id}", "/products/{id}/push"}},
	})
	// Override eBPF tracer to send some fake data
	graph.RegisterStart(gb.builder, func(_ context.Context, _ ebpfcommon.TracerConfig) (node.StartFuncCtx[[]ebpfcommon.HTTPRequestTrace], error) {
		return func(_ context.Context, out chan<- []ebpfcommon.HTTPRequestTrace) {
			out <- newRequest(1, "GET", "/user/1234", "1.1.1.1:3456", 200)
			out <- newRequest(2, "GET", "/products/3210/push", "1.1.1.1:3456", 200)
			out <- newRequest(3, "GET", "/attach", "1.1.1.1:3456", 200) // undefined route: won't report as route
		}, nil
	})
	pipe, err := gb.buildGraph(ctx)
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
			string(semconv.HTTPMethodKey):     "GET",
			string(semconv.HTTPStatusCodeKey): "200",
			string(semconv.HTTPRouteKey):      "/user/{id}",
		},
		Type: pmetric.MetricTypeHistogram,
	}, events["/user/{id}"])

	assert.Equal(t, collector.MetricRecord{
		Name: "http.server.duration",
		Unit: "s",
		Attributes: map[string]string{
			string(semconv.HTTPMethodKey):     "GET",
			string(semconv.HTTPStatusCodeKey): "200",
			string(semconv.HTTPRouteKey):      "/products/{id}/push",
		},
		Type: pmetric.MetricTypeHistogram,
	}, events["/products/{id}/push"])

	assert.Equal(t, collector.MetricRecord{
		Name: "http.server.duration",
		Unit: "s",
		Attributes: map[string]string{
			string(semconv.HTTPMethodKey):     "GET",
			string(semconv.HTTPStatusCodeKey): "200",
			string(semconv.HTTPRouteKey):      "*",
		},
		Type: pmetric.MetricTypeHistogram,
	}, events["*"])
}

func TestGRPCPipeline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tc, err := collector.Start(ctx)
	require.NoError(t, err)

	gb := newGraphBuilder(&Config{Metrics: otel.MetricsConfig{MetricsEndpoint: tc.ServerEndpoint, ReportTarget: true, ReportPeerInfo: true}})
	// Override eBPF tracer to send some fake data
	graph.RegisterStart(gb.builder, func(_ context.Context, _ ebpfcommon.TracerConfig) (node.StartFuncCtx[[]ebpfcommon.HTTPRequestTrace], error) {
		return func(_ context.Context, out chan<- []ebpfcommon.HTTPRequestTrace) {
			out <- newGRPCRequest(1, "/foo/bar", 3)
		}, nil
	})
	pipe, err := gb.buildGraph(ctx)
	require.NoError(t, err)

	go pipe.Run(ctx)

	event := testutil.ReadChannel(t, tc.Records, testTimeout)
	assert.Equal(t, collector.MetricRecord{
		Name: "rpc.server.duration",
		Unit: "s",
		Attributes: map[string]string{
			string(semconv.RPCSystemKey):         "grpc",
			string(semconv.RPCGRPCStatusCodeKey): "3",
			string(semconv.RPCMethodKey):         "/foo/bar",
			string(semconv.NetSockPeerAddrKey):   "1.1.1.1",
		},
		Type: pmetric.MetricTypeHistogram,
	}, event)
}

func TestTraceGRPCPipeline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tc, err := collector.Start(ctx)
	require.NoError(t, err)

	gb := newGraphBuilder(&Config{Traces: otel.TracesConfig{TracesEndpoint: tc.ServerEndpoint, ServiceName: "test"}})
	// Override eBPF tracer to send some fake data
	graph.RegisterStart(gb.builder, func(_ context.Context, _ ebpfcommon.TracerConfig) (node.StartFuncCtx[[]ebpfcommon.HTTPRequestTrace], error) {
		return func(_ context.Context, out chan<- []ebpfcommon.HTTPRequestTrace) {
			out <- newGRPCRequest(1, "foo.bar", 3)
		}, nil
	})
	pipe, err := gb.buildGraph(ctx)
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

	gb := newGraphBuilder(&Config{Traces: otel.TracesConfig{TracesEndpoint: tc.ServerEndpoint, ServiceName: "test"}})
	// Override eBPF tracer to send some fake data with nested client span
	graph.RegisterStart(gb.builder, func(_ context.Context, _ ebpfcommon.TracerConfig) (node.StartFuncCtx[[]ebpfcommon.HTTPRequestTrace], error) {
		return func(_ context.Context, out chan<- []ebpfcommon.HTTPRequestTrace) {
			out <- newRequestWithTiming(1, transform.EventTypeHTTPClient, "GET", "/attach", "2.2.2.2:1234", 200, 60000, 60000, 70000)
			out <- newRequestWithTiming(1, transform.EventTypeHTTP, "GET", "/user/1234", "1.1.1.1:3456", 200, 10000, 10000, 50000)
			out <- newRequestWithTiming(3, transform.EventTypeHTTPClient, "GET", "/products/3210/pull", "2.2.2.2:3456", 204, 80000, 80000, 90000)
			out <- newRequestWithTiming(3, transform.EventTypeHTTPClient, "GET", "/products/3211/pull", "2.2.2.2:3456", 203, 80000, 80000, 90000)
			out <- newRequestWithTiming(2, transform.EventTypeHTTP, "GET", "/products/3210/push", "1.1.1.1:3456", 200, 10000, 20000, 50000)
			out <- newRequestWithTiming(3, transform.EventTypeHTTP, "GET", "/attach", "1.1.1.1:3456", 200, 70000, 80000, 100000)
			out <- newRequestWithTiming(1, transform.EventTypeHTTPClient, "GET", "/attach2", "2.2.2.2:1234", 200, 30000, 30000, 40000)
			out <- newRequestWithTiming(0, transform.EventTypeHTTPClient, "GET", "/attach1", "2.2.2.2:1234", 200, 20000, 20000, 40000)
			out <- newRequestWithTiming(1, transform.EventTypeHTTP, "GET", "/user/3456", "1.1.1.1:3456", 200, 56000, 56000, 80000)
		}, nil
	})
	pipe, err := gb.buildGraph(ctx)
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

func newRequest(id uint64, method, path, peer string, status int) []ebpfcommon.HTTPRequestTrace {
	rt := ebpfcommon.HTTPRequestTrace{}
	copy(rt.Path[:], path)
	copy(rt.Method[:], method)
	copy(rt.RemoteAddr[:], peer)
	copy(rt.Host[:], getHostname()+":8080")
	rt.Status = uint16(status)
	rt.Type = uint8(transform.EventTypeHTTP)
	rt.Id = id
	rt.GoStartMonotimeNs = 1
	rt.StartMonotimeNs = 2
	rt.EndMonotimeNs = 3
	return []ebpfcommon.HTTPRequestTrace{rt}
}

func newRequestWithTiming(id uint64, kind transform.EventType, method, path, peer string, status int, goStart, start, end uint64) []ebpfcommon.HTTPRequestTrace {
	rt := ebpfcommon.HTTPRequestTrace{}
	copy(rt.Path[:], path)
	copy(rt.Method[:], method)
	copy(rt.RemoteAddr[:], peer)
	copy(rt.Host[:], getHostname()+":8080")
	rt.Status = uint16(status)
	rt.Type = uint8(kind)
	rt.Id = id
	rt.GoStartMonotimeNs = goStart
	rt.StartMonotimeNs = start
	rt.EndMonotimeNs = end
	return []ebpfcommon.HTTPRequestTrace{rt}
}

func newGRPCRequest(id uint64, path string, status int) []ebpfcommon.HTTPRequestTrace {
	rt := ebpfcommon.HTTPRequestTrace{}
	copy(rt.Path[:], path)
	copy(rt.RemoteAddr[:], []byte{0x1, 0x1, 0x1, 0x1})
	rt.RemoteAddrLen = 4
	copy(rt.Host[:], []byte{0x7f, 0x0, 0x0, 0x1})
	rt.HostLen = 4
	rt.HostPort = 8080
	rt.Status = uint16(status)
	rt.Type = uint8(transform.EventTypeGRPC)
	rt.Id = id
	rt.GoStartMonotimeNs = 1
	rt.StartMonotimeNs = 2
	rt.EndMonotimeNs = 3
	return []ebpfcommon.HTTPRequestTrace{rt}
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return ""
	}
	return hostname
}

func matchTraceEvent(t *testing.T, name string, event collector.TraceRecord) {
	assert.Equal(t, collector.TraceRecord{
		Name: name,
		Attributes: map[string]string{
			string(semconv.HTTPMethodKey):               "GET",
			string(semconv.HTTPStatusCodeKey):           "404",
			string(semconv.HTTPTargetKey):               "/foo/bar",
			string(semconv.NetSockPeerAddrKey):          "1.1.1.1",
			string(semconv.NetHostNameKey):              getHostname(),
			string(semconv.NetHostPortKey):              "8080",
			string(semconv.HTTPRequestContentLengthKey): "0",
			"span_id":        event.Attributes["span_id"],
			"parent_span_id": event.Attributes["parent_span_id"],
		},
		Kind: ptrace.SpanKindServer,
	}, event)
}

func matchInnerTraceEvent(t *testing.T, name string, event collector.TraceRecord) {
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
			string(semconv.NetSockPeerAddrKey):   "1.1.1.1",
			string(semconv.NetHostNameKey):       "127.0.0.1",
			string(semconv.NetHostPortKey):       "8080",
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
	assert.Equal(t, method, event.Attributes["http.method"])
	assert.Equal(t, status, event.Attributes["http.status_code"])
	if kind == ptrace.SpanKindClient {
		assert.Equal(t, target, event.Attributes["http.url"])
	} else {
		assert.Equal(t, target, event.Attributes["http.target"])
	}
	assert.Equal(t, kind, event.Kind)
}

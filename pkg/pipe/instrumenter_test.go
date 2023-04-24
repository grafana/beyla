package pipe

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/mariomac/pipes/pkg/graph"
	"github.com/mariomac/pipes/pkg/node"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"

	"github.com/grafana/ebpf-autoinstrument/pkg/ebpf/nethttp"
	"github.com/grafana/ebpf-autoinstrument/pkg/export/otel"
	"github.com/grafana/ebpf-autoinstrument/pkg/goexec"
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
	gb.inspector = func(_ goexec.ProcessFinder, _ map[string][]string) (goexec.Offsets, error) {
		return goexec.Offsets{FileInfo: goexec.FileInfo{CmdExePath: "test-service"}}, nil
	}
	// Override eBPF tracer to send some fake data
	graph.RegisterStart(gb.builder, func(_ nethttp.EBPFTracer) node.StartFuncCtx[[]nethttp.HTTPRequestTrace] {
		return func(_ context.Context, out chan<- []nethttp.HTTPRequestTrace) {
			out <- newRequest("GET", "/foo/bar", "1.1.1.1:3456", 404)
		}
	})
	pipe, err := gb.buildGraph()
	require.NoError(t, err)

	go pipe.Run(ctx)

	event := getEvent(t, tc)
	assert.Equal(t, collector.MetricRecord{
		Name: "http.server.duration",
		Unit: "ms",
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
	gb.inspector = func(_ goexec.ProcessFinder, _ map[string][]string) (goexec.Offsets, error) {
		return goexec.Offsets{FileInfo: goexec.FileInfo{CmdExePath: "test-service"}}, nil
	}
	// Override eBPF tracer to send some fake data
	graph.RegisterStart(gb.builder, func(_ nethttp.EBPFTracer) node.StartFuncCtx[[]nethttp.HTTPRequestTrace] {
		return func(_ context.Context, out chan<- []nethttp.HTTPRequestTrace) {
			out <- newRequest("GET", "/foo/bar", "1.1.1.1:3456", 404)
		}
	})
	pipe, err := gb.buildGraph()
	require.NoError(t, err)

	go pipe.Run(ctx)

	event := getTraceEvent(t, tc)
	matchInnerTraceEvent(t, "in queue", event)
	event = getTraceEvent(t, tc)
	matchInnerTraceEvent(t, "processing", event)
	event = getTraceEvent(t, tc)
	matchTraceEvent(t, "session", event)
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
	gb.inspector = func(_ goexec.ProcessFinder, _ map[string][]string) (goexec.Offsets, error) {
		return goexec.Offsets{FileInfo: goexec.FileInfo{CmdExePath: "test-service"}}, nil
	}
	// Override eBPF tracer to send some fake data
	graph.RegisterStart(gb.builder, func(_ nethttp.EBPFTracer) node.StartFuncCtx[[]nethttp.HTTPRequestTrace] {
		return func(_ context.Context, out chan<- []nethttp.HTTPRequestTrace) {
			out <- newRequest("GET", "/user/1234", "1.1.1.1:3456", 200)
			out <- newRequest("GET", "/products/3210/push", "1.1.1.1:3456", 200)
			out <- newRequest("GET", "/attach", "1.1.1.1:3456", 200) // undefined route: won't report as route
		}
	})
	pipe, err := gb.buildGraph()
	require.NoError(t, err)

	go pipe.Run(ctx)

	// expect to receive 3 events without any guaranteed order
	events := map[string]collector.MetricRecord{}
	for i := 0; i < 3; i++ {
		ev := getEvent(t, tc)
		events[ev.Attributes[string(semconv.HTTPRouteKey)]] = ev
	}

	assert.Equal(t, collector.MetricRecord{
		Name: "http.server.duration",
		Unit: "ms",
		Attributes: map[string]string{
			string(semconv.HTTPMethodKey):     "GET",
			string(semconv.HTTPStatusCodeKey): "200",
			string(semconv.HTTPRouteKey):      "/user/{id}",
		},
		Type: pmetric.MetricTypeHistogram,
	}, events["/user/{id}"])

	assert.Equal(t, collector.MetricRecord{
		Name: "http.server.duration",
		Unit: "ms",
		Attributes: map[string]string{
			string(semconv.HTTPMethodKey):     "GET",
			string(semconv.HTTPStatusCodeKey): "200",
			string(semconv.HTTPRouteKey):      "/products/{id}/push",
		},
		Type: pmetric.MetricTypeHistogram,
	}, events["/products/{id}/push"])

	assert.Equal(t, collector.MetricRecord{
		Name: "http.server.duration",
		Unit: "ms",
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
	gb.inspector = func(_ goexec.ProcessFinder, _ map[string][]string) (goexec.Offsets, error) {
		return goexec.Offsets{FileInfo: goexec.FileInfo{CmdExePath: "test-service"}}, nil
	}
	// Override eBPF tracer to send some fake data
	graph.RegisterStart(gb.builder, func(_ nethttp.EBPFTracer) node.StartFuncCtx[[]nethttp.HTTPRequestTrace] {
		return func(_ context.Context, out chan<- []nethttp.HTTPRequestTrace) {
			out <- newGRPCRequest("/foo/bar", 3)
		}
	})
	pipe, err := gb.buildGraph()
	require.NoError(t, err)

	go pipe.Run(ctx)

	event := getEvent(t, tc)
	assert.Equal(t, collector.MetricRecord{
		Name: "rpc.server.duration",
		Unit: "ms",
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
	gb.inspector = func(_ goexec.ProcessFinder, _ map[string][]string) (goexec.Offsets, error) {
		return goexec.Offsets{FileInfo: goexec.FileInfo{CmdExePath: "test-service"}}, nil
	}
	// Override eBPF tracer to send some fake data
	graph.RegisterStart(gb.builder, func(_ nethttp.EBPFTracer) node.StartFuncCtx[[]nethttp.HTTPRequestTrace] {
		return func(_ context.Context, out chan<- []nethttp.HTTPRequestTrace) {
			out <- newGRPCRequest("/foo/bar", 3)
		}
	})
	pipe, err := gb.buildGraph()
	require.NoError(t, err)

	go pipe.Run(ctx)

	event := getTraceEvent(t, tc)
	matchInnerGRPCTraceEvent(t, "in queue", event)
	event = getTraceEvent(t, tc)
	matchInnerGRPCTraceEvent(t, "processing", event)
	event = getTraceEvent(t, tc)
	matchGRPCTraceEvent(t, "session", event)
}

func newRequest(method, path, peer string, status int) []nethttp.HTTPRequestTrace {
	rt := nethttp.HTTPRequestTrace{}
	copy(rt.Path[:], path)
	copy(rt.Method[:], method)
	copy(rt.RemoteAddr[:], peer)
	copy(rt.Host[:], getHostname()+":8080")
	rt.Status = uint16(status)
	rt.Type = transform.EventTypeHTTP
	return []nethttp.HTTPRequestTrace{rt}
}

func newGRPCRequest(path string, status int) []nethttp.HTTPRequestTrace {
	rt := nethttp.HTTPRequestTrace{}
	copy(rt.Path[:], path)
	copy(rt.RemoteAddr[:], []byte{0x1, 0x1, 0x1, 0x1})
	rt.RemoteAddrLen = 4
	copy(rt.Host[:], []byte{0x7f, 0x0, 0x0, 0x1})
	rt.HostLen = 4
	rt.HostPort = 8080
	rt.Status = uint16(status)
	rt.Type = transform.EventTypeGRPC
	return []nethttp.HTTPRequestTrace{rt}
}

func getEvent(t *testing.T, coll *collector.TestCollector) collector.MetricRecord {
	t.Helper()
	select {
	case ev := <-coll.Records:
		return ev
	case <-time.After(testTimeout):
		t.Fatal("timeout while waiting for message")
	}
	return collector.MetricRecord{}
}

func getTraceEvent(t *testing.T, coll *collector.TestCollector) collector.TraceRecord {
	t.Helper()
	select {
	case ev := <-coll.TraceRecords:
		return ev
	case <-time.After(testTimeout):
		t.Fatal("timeout while waiting for message")
	}
	return collector.TraceRecord{}
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
		},
		Kind: ptrace.SpanKindServer,
	}, event)
}

func matchInnerTraceEvent(t *testing.T, name string, event collector.TraceRecord) {
	assert.Equal(t, collector.TraceRecord{
		Name:       name,
		Attributes: map[string]string{},
		Kind:       ptrace.SpanKindInternal,
	}, event)
}

func matchGRPCTraceEvent(t *testing.T, name string, event collector.TraceRecord) {
	assert.Equal(t, collector.TraceRecord{
		Name: name,
		Attributes: map[string]string{
			string(semconv.RPCSystemKey):         "grpc",
			string(semconv.RPCGRPCStatusCodeKey): "3",
			string(semconv.RPCMethodKey):         "/foo/bar",
			string(semconv.NetSockPeerAddrKey):   "1.1.1.1",
			string(semconv.NetHostNameKey):       "127.0.0.1",
			string(semconv.NetHostPortKey):       "8080",
		},
		Kind: ptrace.SpanKindServer,
	}, event)
}

func matchInnerGRPCTraceEvent(t *testing.T, name string, event collector.TraceRecord) {
	assert.Equal(t, collector.TraceRecord{
		Name:       name,
		Attributes: map[string]string{},
		Kind:       ptrace.SpanKindInternal,
	}, event)
}

package pipe

import (
	"context"
	"testing"
	"time"

	"github.com/mariomac/pipes/pkg/graph"
	"github.com/mariomac/pipes/pkg/node"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pmetric"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"

	"github.com/grafana/http-autoinstrument/pkg/ebpf/nethttp"
	"github.com/grafana/http-autoinstrument/pkg/export/otel"
	"github.com/grafana/http-autoinstrument/pkg/goexec"
	"github.com/grafana/http-autoinstrument/pkg/transform"
	"github.com/grafana/http-autoinstrument/test/collector"
)

const testTimeout = 5 * time.Second

func TestBasicPipeline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tc, err := collector.Start(ctx)
	require.NoError(t, err)

	gb := newGraphBuilder(&Config{Metrics: otel.MetricsConfig{MetricsEndpoint: tc.ServerHostPort, ReportTarget: true}})
	gb.inspector = func(_ string, _ []string) (goexec.Offsets, error) {
		return goexec.Offsets{FileInfo: goexec.FileInfo{CmdExePath: "test-service"}}, nil
	}
	// Override eBPF tracer to send some fake data
	graph.RegisterStart(gb.builder, func(_ nethttp.EBPFTracer) node.StartFuncCtx[nethttp.HTTPRequestTrace] {
		return func(_ context.Context, out chan<- nethttp.HTTPRequestTrace) {
			out <- newRequest("GET", "/foo/bar", "1.1.1.1:3456", 404)
		}
	})
	pipe, err := gb.buildGraph()
	require.NoError(t, err)

	go pipe.Run(ctx)

	event := getEvent(t, tc)
	assert.Equal(t, collector.MetricRecord{
		Name: "duration",
		Unit: "ms",
		Attributes: map[string]string{
			string(semconv.HTTPMethodKey):     "GET",
			string(semconv.HTTPStatusCodeKey): "404",
			string(semconv.HTTPTargetKey):     "/foo/bar",
			string(semconv.NetPeerNameKey):    "1.1.1.1",
			string(semconv.NetPeerPortKey):    "3456",
		},
		Type: pmetric.MetricTypeHistogram,
	}, event)
}

func TestRouteConsolidation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tc, err := collector.Start(ctx)
	require.NoError(t, err)

	gb := newGraphBuilder(&Config{
		Metrics: otel.MetricsConfig{MetricsEndpoint: tc.ServerHostPort},
		Routes:  &transform.RoutesConfig{Patterns: []string{"/user/{id}", "/products/{id}/push"}},
	})
	gb.inspector = func(_ string, _ []string) (goexec.Offsets, error) {
		return goexec.Offsets{FileInfo: goexec.FileInfo{CmdExePath: "test-service"}}, nil
	}
	// Override eBPF tracer to send some fake data
	graph.RegisterStart(gb.builder, func(_ nethttp.EBPFTracer) node.StartFuncCtx[nethttp.HTTPRequestTrace] {
		return func(_ context.Context, out chan<- nethttp.HTTPRequestTrace) {
			out <- newRequest("GET", "/user/1234", 200)
			out <- newRequest("GET", "/products/3210/push", 200)
			out <- newRequest("GET", "/attach", 200) // undefined route: won't report as route
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
		Name: "duration",
		Unit: "ms",
		Attributes: map[string]string{
			string(semconv.HTTPMethodKey):     "GET",
			string(semconv.HTTPStatusCodeKey): "200",
			string(semconv.HTTPRouteKey):      "/user/{id}",
		},
		Type: pmetric.MetricTypeHistogram,
	}, events["/user/{id}"])

	assert.Equal(t, collector.MetricRecord{
		Name: "duration",
		Unit: "ms",
		Attributes: map[string]string{
			string(semconv.HTTPMethodKey):     "GET",
			string(semconv.HTTPStatusCodeKey): "200",
			string(semconv.HTTPRouteKey):      "/products/{id}/push",
		},
		Type: pmetric.MetricTypeHistogram,
	}, events["/products/{id}/push"])

	assert.Equal(t, collector.MetricRecord{
		Name: "duration",
		Unit: "ms",
		Attributes: map[string]string{
			string(semconv.HTTPMethodKey):     "GET",
			string(semconv.HTTPStatusCodeKey): "200",
			string(semconv.HTTPRouteKey):      "*",
		},
		Type: pmetric.MetricTypeHistogram,
	}, events["*"])
}

func newRequest(method, path string, status int) nethttp.HTTPRequestTrace {
	rt := nethttp.HTTPRequestTrace{}
	copy(rt.Path[:], path)
	copy(rt.Method[:], method)
	rt.Status = uint16(status)
	return rt
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

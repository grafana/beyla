package pipe

import (
	"context"
	"testing"
	"time"

	"github.com/grafana/http-autoinstrument/pkg/ebpf/export/otel"

	"github.com/grafana/http-autoinstrument/pkg/ebpf/nethttp"
	"github.com/grafana/http-autoinstrument/pkg/goexec"
	"github.com/grafana/http-autoinstrument/test/collector"
	"github.com/mariomac/pipes/pkg/graph"
	"github.com/mariomac/pipes/pkg/node"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pmetric"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
)

const testTimeout = 5 * time.Second

func TestBasicPipeline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tc, err := collector.Start(ctx)
	require.NoError(t, err)

	gb := newGraphBuilder(&Config{Metrics: otel.MetricsConfig{MetricsEndpoint: tc.ServerHostPort}})
	gb.inspector = func(_ string, _ []string) (goexec.Offsets, error) {
		return goexec.Offsets{FileInfo: goexec.FileInfo{CmdExePath: "test-service"}}, nil
	}
	// Override eBPF tracer to send some fake data
	graph.RegisterStart(gb.builder, func(_ nethttp.EBPFTracer) node.StartFuncCtx[nethttp.HTTPRequestTrace] {
		return func(_ context.Context, out chan<- nethttp.HTTPRequestTrace) {
			rt := nethttp.HTTPRequestTrace{}
			copy(rt.Path[:], "/foo/bar")
			copy(rt.Method[:], "GET")
			copy(rt.RemoteAddr[:], "1.1.1.1:3456")
			rt.Status = 404
			out <- rt
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

func getEvent(t *testing.T, coll *collector.TestCollector) collector.MetricRecord {
	select {
	case ev := <-coll.Records:
		return ev
	case <-time.After(testTimeout):
		t.Fatal("timeout while waiting for message")
	}
	return collector.MetricRecord{}
}

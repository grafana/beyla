package pipe

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/pmetric"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"

	"github.com/grafana/http-autoinstrument/test/collector"

	"github.com/stretchr/testify/require"

	"github.com/grafana/http-autoinstrument/pkg/ebpf/nethttp"
	"github.com/mariomac/pipes/pkg/node"

	"github.com/stretchr/testify/assert"
)

const testTimeout = 5 * time.Second

func TestConfigValidate(t *testing.T) {
	testCases := []Config{
		{OTELEndpoint: "localhost:1234", Exec: "foo", FuncName: "bar"},
		{OTELMetricsEndpoint: "localhost:1234", Exec: "foo", FuncName: "bar"},
		{OTELTracesEndpoint: "localhost:1234", Exec: "foo", FuncName: "bar"},
		{PrintTraces: true, Exec: "foo", FuncName: "bar"},
	}
	for n, tc := range testCases {
		t.Run(fmt.Sprint("case", n), func(t *testing.T) {
			assert.NoError(t, tc.Validate())
		})
	}
}

func TestConfigValidate_error(t *testing.T) {
	testCases := []Config{
		{OTELEndpoint: "localhost:1234", FuncName: "bar"},
		{OTELMetricsEndpoint: "localhost:1234", Exec: "foo"},
		{Exec: "foo", FuncName: "bar"},
	}
	for n, tc := range testCases {
		t.Run(fmt.Sprint("case", n), func(t *testing.T) {
			_, err := Build(&tc)
			assert.Error(t, err)
		})
	}
}

func TestBasicPipeline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tc, err := collector.Start(ctx)
	require.NoError(t, err)

	gb := graphBuilder{
		config: &Config{
			OTELEndpoint: tc.ServerHostPort,
		},
		svcName: "test-service",
		tracerNode: func(_ *graphBuilder) (*node.Start[nethttp.HTTPRequestTrace], error) {
			return node.AsStart(func(out chan<- nethttp.HTTPRequestTrace) {
				rt := nethttp.HTTPRequestTrace{}
				copy(rt.Path[:], "/foo/bar")
				copy(rt.Method[:], "GET")
				rt.Status = 404
				out <- rt
			}), nil
		},
		exporterNodes: otelExporters,
	}
	graph, err := gb.buildGraph()
	require.NoError(t, err)

	go graph.Start(ctx)

	event := getEvent(t, tc)
	assert.Equal(t, collector.MetricRecord{
		Name: "duration",
		Unit: "ms",
		Attributes: map[string]string{
			string(semconv.HTTPMethodKey):     "GET",
			string(semconv.HTTPStatusCodeKey): "404",
			string(semconv.HTTPTargetKey):     "/foo/bar",
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

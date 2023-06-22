package otel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/mariomac/pipes/pkg/node"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"

	"github.com/grafana/ebpf-autoinstrument/pkg/imetrics"
	"github.com/grafana/ebpf-autoinstrument/pkg/pipe/global"
	"github.com/grafana/ebpf-autoinstrument/pkg/transform"
)

const timeout = 5000 * time.Second

func TestMetricsEndpoint(t *testing.T) {
	mcfg := MetricsConfig{
		ServiceName:     "svc-name",
		Endpoint:        "https://localhost:3131",
		MetricsEndpoint: "https://localhost:3232",
	}

	t.Run("testing with two endpoints", func(t *testing.T) {
		testMetricsEndpLen(t, 1, &mcfg)
	})

	mcfg = MetricsConfig{
		ServiceName:     "svc-name",
		Endpoint:        "https://localhost:3131",
		MetricsEndpoint: "https://localhost:3232",
	}

	t.Run("testing with only metrics endpoint", func(t *testing.T) {
		testMetricsEndpLen(t, 1, &mcfg)
	})

	mcfg.Endpoint = "https://localhost:3131"
	mcfg.MetricsEndpoint = ""

	t.Run("testing with only non-signal endpoint", func(t *testing.T) {
		testMetricsEndpLen(t, 1, &mcfg)
	})

	mcfg.Endpoint = "http://localhost:3131"
	t.Run("testing with insecure endpoint", func(t *testing.T) {
		testMetricsEndpLen(t, 2, &mcfg)
	})

	mcfg.Endpoint = "http://localhost:3131/path_to_endpoint"
	t.Run("testing with insecure endpoint and path", func(t *testing.T) {
		testMetricsEndpLen(t, 3, &mcfg)
	})

	mcfg.Endpoint = "http://localhost:3131/v1/metrics"
	t.Run("testing with insecure endpoint and containing v1/metrics", func(t *testing.T) {
		testMetricsEndpLen(t, 2, &mcfg)
	})
}

func testMetricsEndpLen(t *testing.T, expected int, mcfg *MetricsConfig) {
	opts, err := getMetricEndpointOptions(mcfg)
	require.NoError(t, err)
	// otlptracehttp.Options are notoriously hard to compare, so we just test the length
	assert.Equal(t, expected, len(opts))
}

func TestMissingSchemeInMetricsEndpoint(t *testing.T) {
	opts, err := getMetricEndpointOptions(&MetricsConfig{Endpoint: "http://foo:3030"})
	require.NoError(t, err)
	require.NotEmpty(t, opts)

	_, err = getMetricEndpointOptions(&MetricsConfig{Endpoint: "foo:3030"})
	require.Error(t, err)

	_, err = getMetricEndpointOptions(&MetricsConfig{Endpoint: "foo"})
	require.Error(t, err)
}

func TestInternalInstrumentation(t *testing.T) {
	// fake OTEL collector server
	coll := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}))
	defer coll.Close()
	// create a simple dummy graph to send data to the Metrics reporter, which will send
	// metrics to the fake collector
	sendData := make(chan struct{})
	inputNode := node.AsStart(func(out chan<- []transform.HTTPRequestSpan) {
		// on every send data signal, the traces generator sends a dummy trace
		for range sendData {
			out <- []transform.HTTPRequestSpan{{Type: transform.EventTypeHTTP}}
		}
	})
	internalMetrics := &fakeInternalMetrics{}
	exporter, err := MetricsReporterProvider(global.SetContext(context.Background(), &global.ContextInfo{
		ServiceName: "foo",
		Metrics:     internalMetrics,
	}), MetricsConfig{Endpoint: coll.URL, Interval: 10 * time.Millisecond})
	require.NoError(t, err)
	inputNode.SendsTo(node.AsTerminal(exporter))
	go inputNode.Start()

	sendData <- struct{}{}
	var previousCount, previousCalls int
	test.Eventually(t, timeout, func(t require.TestingT) {
		// we can't guarantee the number of calls at test time, but they must be at least 1
		previousCount, previousCalls = internalMetrics.count, internalMetrics.calls
		assert.LessOrEqual(t, 1, previousCount)
		assert.LessOrEqual(t, 1, previousCalls)
		// the count of metrics should be larger than the number of calls (1 call : n metrics)
		assert.Less(t, previousCalls, previousCount)
		// no call should return error
		assert.Empty(t, internalMetrics.errors)
	})

	sendData <- struct{}{}
	// after some time, the number of calls should be higher than before
	test.Eventually(t, timeout, func(t require.TestingT) {
		assert.LessOrEqual(t, previousCount, internalMetrics.count)
		assert.LessOrEqual(t, previousCalls, internalMetrics.calls)
		assert.Less(t, internalMetrics.calls, internalMetrics.count)
		// no call should return error
		assert.Empty(t, internalMetrics.errors)
	})

	// collector starts failing, so errors should be received
	coll.CloseClientConnections()
	coll.Close()

	var previousErrors map[string]int
	var previousErrCount int
	sendData <- struct{}{}
	test.Eventually(t, timeout, func(t require.TestingT) {
		previousCount, previousCalls = internalMetrics.count, internalMetrics.calls
		// calls should start returning errors
		previousErrors = maps.Clone(internalMetrics.errors)
		assert.Len(t, previousErrors, 1)
		for _, v := range previousErrors {
			previousErrCount = v
		}
	})

	// after a while, metrics count should not increase but errors do
	sendData <- struct{}{}
	test.Eventually(t, timeout, func(t require.TestingT) {
		assert.Equal(t, previousCount, internalMetrics.count)
		assert.Equal(t, previousCalls, internalMetrics.calls)
		// calls should start returning errors
		assert.Len(t, previousErrors, 1)
		for _, v := range internalMetrics.errors {
			assert.Less(t, previousErrCount, v)
		}
	})
}

type fakeInternalMetrics struct {
	imetrics.NoopReporter
	calls  int
	count  int
	errors map[string]int
}

func (f *fakeInternalMetrics) OTELMetricExport(len int) {
	f.calls++
	f.count += len
}

func (f *fakeInternalMetrics) OTELMetricExportError(err error) {
	if f.errors == nil {
		f.errors = map[string]int{}
	}
	f.errors[err.Error()]++
}

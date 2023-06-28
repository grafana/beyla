package otel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
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

const timeout = 5 * time.Second

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

func TestMetrics_InternalInstrumentation(t *testing.T) {
	// fake OTEL collector server
	coll := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}))
	defer coll.Close()
	// Wait for the HTTP server to be alive
	test.Eventually(t, timeout, func(t require.TestingT) {
		resp, err := coll.Client().Get(coll.URL + "/foo")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

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
	var previousSum, previousCount int
	test.Eventually(t, timeout, func(t require.TestingT) {
		// we can't guarantee the number of calls at test time, but they must be at least 1
		previousSum, previousCount = internalMetrics.SumCount()
		assert.LessOrEqual(t, 1, previousSum)
		assert.LessOrEqual(t, 1, previousCount)
		// the count of metrics should be larger than the number of calls (1 call : n metrics)
		assert.Less(t, previousCount, previousSum)
		// no call should return error
		assert.Empty(t, internalMetrics.Errors())
	})

	sendData <- struct{}{}
	// after some time, the number of calls should be higher than before
	test.Eventually(t, timeout, func(t require.TestingT) {
		sum, cnt := internalMetrics.SumCount()
		assert.LessOrEqual(t, previousSum, sum)
		assert.LessOrEqual(t, previousCount, cnt)
		assert.Less(t, cnt, sum)
		// no call should return error
		assert.Empty(t, internalMetrics.Errors())
	})

	// collector starts failing, so errors should be received
	coll.CloseClientConnections()
	coll.Close()
	// Wait for the HTTP server to be stopped
	test.Eventually(t, timeout, func(t require.TestingT) {
		_, err := coll.Client().Get(coll.URL + "/foo")
		require.Error(t, err)
	})

	var previousErrors map[string]int
	var previousErrCount int
	sendData <- struct{}{}
	test.Eventually(t, timeout, func(t require.TestingT) {
		previousSum, previousCount = internalMetrics.SumCount()
		// calls should start returning errors
		previousErrors = maps.Clone(internalMetrics.Errors())
		assert.Len(t, previousErrors, 1)
		for _, v := range previousErrors {
			previousErrCount = v
		}
	})

	// after a while, metrics count should not increase but errors do
	sendData <- struct{}{}
	test.Eventually(t, timeout, func(t require.TestingT) {
		sum, cnt := internalMetrics.SumCount()
		assert.Equal(t, previousSum, sum)
		assert.Equal(t, previousCount, cnt)
		// calls should start returning errors
		assert.Len(t, previousErrors, 1)
		for _, v := range internalMetrics.Errors() {
			assert.Less(t, previousErrCount, v)
		}
	})
}

type fakeInternalMetrics struct {
	imetrics.NoopReporter
	m    sync.RWMutex
	sum  int
	cnt  int
	errs map[string]int
}

func (f *fakeInternalMetrics) OTELMetricExport(len int) {
	f.m.Lock()
	defer f.m.Unlock()
	f.cnt++
	f.sum += len
}

func (f *fakeInternalMetrics) OTELMetricExportError(err error) {
	f.m.Lock()
	defer f.m.Unlock()
	if f.errs == nil {
		f.errs = map[string]int{}
	}
	f.errs[err.Error()]++
}

func (f *fakeInternalMetrics) Errors() map[string]int {
	f.m.RLock()
	defer f.m.RUnlock()
	return maps.Clone(f.errs)
}

func (f *fakeInternalMetrics) SumCount() (sum, count int) {
	f.m.RLock()
	defer f.m.RUnlock()
	return f.sum, f.cnt
}

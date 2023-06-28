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

func TestTracesEndpoint(t *testing.T) {
	tcfg := TracesConfig{
		ServiceName:        "svc-name",
		Endpoint:           "https://localhost:3131",
		TracesEndpoint:     "https://localhost:3232",
		MaxQueueSize:       4096,
		MaxExportBatchSize: 4096,
	}

	t.Run("testing with two endpoints", func(t *testing.T) {
		testTracesEndpLen(t, 1, &tcfg)
	})

	tcfg = TracesConfig{
		ServiceName:        "svc-name",
		TracesEndpoint:     "https://localhost:3232",
		MaxQueueSize:       4096,
		MaxExportBatchSize: 4096,
	}

	t.Run("testing with only trace endpoint", func(t *testing.T) {
		testTracesEndpLen(t, 1, &tcfg)
	})

	tcfg.Endpoint = "https://localhost:3131"
	tcfg.TracesEndpoint = ""

	t.Run("testing with only non-signal endpoint", func(t *testing.T) {
		testTracesEndpLen(t, 1, &tcfg)
	})

	tcfg.Endpoint = "http://localhost:3131"
	t.Run("testing with insecure endpoint", func(t *testing.T) {
		testTracesEndpLen(t, 2, &tcfg)
	})

	tcfg.Endpoint = "http://localhost:3131/path_to_endpoint"
	t.Run("testing with insecure endpoint and path", func(t *testing.T) {
		testTracesEndpLen(t, 3, &tcfg)
	})

	tcfg.Endpoint = "http://localhost:3131/v1/traces"
	t.Run("testing with insecure endpoint and containing v1/traces", func(t *testing.T) {
		testTracesEndpLen(t, 2, &tcfg)
	})
}

func testTracesEndpLen(t *testing.T, expected int, tcfg *TracesConfig) {
	opts, err := getTracesEndpointOptions(tcfg)
	require.NoError(t, err)
	// otlptracehttp.Options are notoriously hard to compare, so we just test the length
	assert.Equal(t, expected, len(opts))
}

func TestMissingSchemeInTracesEndpoint(t *testing.T) {
	opts, err := getTracesEndpointOptions(&TracesConfig{Endpoint: "http://foo:3030"})
	require.NoError(t, err)
	require.NotEmpty(t, opts)

	_, err = getTracesEndpointOptions(&TracesConfig{Endpoint: "foo:3030"})
	require.Error(t, err)

	_, err = getTracesEndpointOptions(&TracesConfig{Endpoint: "foo"})
	require.Error(t, err)
}

func TestTraces_InternalInstrumentation(t *testing.T) {
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
	internalTraces := &fakeInternalTraces{}
	exporter, err := TracesReporterProvider(global.SetContext(context.Background(), &global.ContextInfo{
		ServiceName: "foo",
		Metrics:     internalTraces,
	}), TracesConfig{Endpoint: coll.URL, BatchTimeout: 10 * time.Millisecond, ExportTimeout: 10 * time.Millisecond})
	require.NoError(t, err)
	inputNode.SendsTo(node.AsTerminal(exporter))

	go inputNode.Start()

	sendData <- struct{}{}
	var previousSum, previouscount int
	test.Eventually(t, timeout, func(t require.TestingT) {
		// we can't guarantee the number of calls at test time, but they must be at least 1
		previousSum, previouscount = internalTraces.SumCount()
		assert.LessOrEqual(t, 1, previousSum)
		assert.LessOrEqual(t, 1, previouscount)
		// the sum of metrics should be larger or equal than the number of calls (1 call : n metrics)
		assert.LessOrEqual(t, previouscount, previousSum)
		// no call should return error
		assert.Empty(t, internalTraces.Errors())
	})

	sendData <- struct{}{}
	// after some time, the number of calls should be higher than before
	test.Eventually(t, timeout, func(t require.TestingT) {
		sum, count := internalTraces.SumCount()
		assert.LessOrEqual(t, previousSum, sum)
		assert.LessOrEqual(t, previouscount, count)
		assert.LessOrEqual(t, count, sum)
		// no call should return error
		assert.Empty(t, internalTraces.Errors())
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
		previousSum, previouscount = internalTraces.SumCount()
		// calls should start returning errors
		previousErrors = internalTraces.Errors()
		assert.Len(t, previousErrors, 1)
		for _, v := range previousErrors {
			previousErrCount = v
		}
	})

	// after a while, metrics sum should not increase but errors do
	sendData <- struct{}{}
	test.Eventually(t, timeout, func(t require.TestingT) {
		sum, count := internalTraces.SumCount()
		assert.Equal(t, previousSum, sum)
		assert.Equal(t, previouscount, count)
		// calls should start returning errors
		assert.Len(t, previousErrors, 1)
		for _, v := range internalTraces.Errors() {
			assert.Less(t, previousErrCount, v)
		}
	})
}

type fakeInternalTraces struct {
	imetrics.NoopReporter
	m     sync.RWMutex
	count int
	sum   int
	errs  map[string]int
}

func (f *fakeInternalTraces) OTELTraceExport(len int) {
	f.m.Lock()
	defer f.m.Unlock()
	f.count++
	f.sum += len
}

func (f *fakeInternalTraces) OTELTraceExportError(err error) {
	f.m.Lock()
	defer f.m.Unlock()
	if f.errs == nil {
		f.errs = map[string]int{}
	}
	f.errs[err.Error()]++
}

func (f *fakeInternalTraces) Errors() map[string]int {
	f.m.RLock()
	defer f.m.RUnlock()
	return maps.Clone(f.errs)
}

func (f *fakeInternalTraces) SumCount() (sum, count int) {
	f.m.RLock()
	defer f.m.RUnlock()
	return f.sum, f.count
}

package otel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/grafana/ebpf-autoinstrument/pkg/imetrics"
	"github.com/grafana/ebpf-autoinstrument/pkg/pipe/global"
	"github.com/grafana/ebpf-autoinstrument/pkg/transform"
	"github.com/mariomac/guara/pkg/test"
	"github.com/mariomac/pipes/pkg/node"
	"golang.org/x/exp/maps"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	var previousCount, previousCalls int
	test.Eventually(t, timeout, func(t require.TestingT) {
		// we can't guarantee the number of calls at test time, but they must be at least 1
		previousCount, previousCalls = internalTraces.count, internalTraces.calls
		assert.LessOrEqual(t, 1, previousCount)
		assert.LessOrEqual(t, 1, previousCalls)
		// the count of metrics should be larger or equal than the number of calls (1 call : n metrics)
		assert.LessOrEqual(t, previousCalls, previousCount)
		// no call should return error
		assert.Empty(t, internalTraces.errors)
	})

	sendData <- struct{}{}
	// after some time, the number of calls should be higher than before
	test.Eventually(t, timeout, func(t require.TestingT) {
		assert.LessOrEqual(t, previousCount, internalTraces.count)
		assert.LessOrEqual(t, previousCalls, internalTraces.calls)
		assert.LessOrEqual(t, internalTraces.calls, internalTraces.count)
		// no call should return error
		assert.Empty(t, internalTraces.errors)
	})

	// collector starts failing, so errors should be received
	coll.CloseClientConnections()
	coll.Close()

	var previousErrors map[string]int
	var previousErrCount int
	sendData <- struct{}{}
	test.Eventually(t, timeout, func(t require.TestingT) {
		previousCount, previousCalls = internalTraces.count, internalTraces.calls
		// calls should start returning errors
		previousErrors = maps.Clone(internalTraces.errors)
		assert.Len(t, previousErrors, 1)
		for _, v := range previousErrors {
			previousErrCount = v
		}
	})

	// after a while, metrics count should not increase but errors do
	sendData <- struct{}{}
	test.Eventually(t, timeout, func(t require.TestingT) {
		assert.Equal(t, previousCount, internalTraces.count)
		assert.Equal(t, previousCalls, internalTraces.calls)
		// calls should start returning errors
		assert.Len(t, previousErrors, 1)
		for _, v := range internalTraces.errors {
			assert.Less(t, previousErrCount, v)
		}
	})
}

type fakeInternalTraces struct {
	imetrics.NoopReporter
	calls  int
	count  int
	errors map[string]int
}

func (f *fakeInternalTraces) OTELTraceExport(len int) {
	f.calls++
	f.count += len
}

func (f *fakeInternalTraces) OTELTraceExportError(err error) {
	if f.errors == nil {
		f.errors = map[string]int{}
	}
	f.errors[err.Error()]++
}

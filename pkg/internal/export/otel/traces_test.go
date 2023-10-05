package otel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/mariomac/pipes/pkg/node"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	trace2 "go.opentelemetry.io/otel/trace"

	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/request"
)

func TestHTTPTracesEndpoint(t *testing.T) {
	defer restoreEnvAfterExecution()()
	tcfg := TracesConfig{
		CommonEndpoint: "https://localhost:3131",
		TracesEndpoint: "https://localhost:3232/v1/traces",
	}

	t.Run("testing with two endpoints", func(t *testing.T) {
		testHTTPTracesOptions(t, otlpOptions{Endpoint: "localhost:3232", URLPath: "/v1/traces"}, &tcfg)
	})

	tcfg = TracesConfig{
		CommonEndpoint: "https://localhost:3131/otlp",
	}

	t.Run("testing with only common endpoint", func(t *testing.T) {
		testHTTPTracesOptions(t, otlpOptions{Endpoint: "localhost:3131", URLPath: "/otlp/v1/traces"}, &tcfg)
	})

	tcfg = TracesConfig{
		CommonEndpoint: "https://localhost:3131",
		TracesEndpoint: "http://localhost:3232",
	}
	t.Run("testing with insecure endpoint", func(t *testing.T) {
		testHTTPTracesOptions(t, otlpOptions{Endpoint: "localhost:3232", Insecure: true}, &tcfg)
	})

	tcfg = TracesConfig{
		CommonEndpoint:     "https://localhost:3232",
		InsecureSkipVerify: true,
	}

	t.Run("testing with skip TLS verification", func(t *testing.T) {
		testHTTPTracesOptions(t, otlpOptions{Endpoint: "localhost:3232", URLPath: "/v1/traces", SkipTLSVerify: true}, &tcfg)
	})
}

func testHTTPTracesOptions(t *testing.T, expected otlpOptions, tcfg *TracesConfig) {
	defer restoreEnvAfterExecution()()
	opts, err := getHTTPTracesEndpointOptions(tcfg)
	require.NoError(t, err)
	assert.Equal(t, expected, opts)
}

func TestMissingSchemeInHTTPTracesEndpoint(t *testing.T) {
	defer restoreEnvAfterExecution()()
	opts, err := getHTTPTracesEndpointOptions(&TracesConfig{CommonEndpoint: "http://foo:3030", SamplingRatio: 1.0})
	require.NoError(t, err)
	require.NotEmpty(t, opts)

	_, err = getHTTPTracesEndpointOptions(&TracesConfig{CommonEndpoint: "foo:3030", SamplingRatio: 1.0})
	require.Error(t, err)

	_, err = getHTTPTracesEndpointOptions(&TracesConfig{CommonEndpoint: "foo", SamplingRatio: 1.0})
	require.Error(t, err)
}

func TestGRPCTracesEndpointOptions(t *testing.T) {
	defer restoreEnvAfterExecution()()
	t.Run("do not accept URLs without a scheme", func(t *testing.T) {
		_, err := getGRPCTracesEndpointOptions(&TracesConfig{CommonEndpoint: "foo:3939", SamplingRatio: 1.0})
		assert.Error(t, err)
	})
	tcfg := TracesConfig{
		CommonEndpoint: "https://localhost:3131",
		TracesEndpoint: "https://localhost:3232",
	}

	t.Run("testing with two endpoints", func(t *testing.T) {
		testTracesGRPOptions(t, otlpOptions{Endpoint: "localhost:3232"}, &tcfg)
	})

	tcfg = TracesConfig{
		CommonEndpoint: "https://localhost:3131",
	}

	t.Run("testing with only common endpoint", func(t *testing.T) {
		testTracesGRPOptions(t, otlpOptions{Endpoint: "localhost:3131"}, &tcfg)
	})

	tcfg = TracesConfig{
		CommonEndpoint: "https://localhost:3131",
		TracesEndpoint: "http://localhost:3232",
	}
	t.Run("testing with insecure endpoint", func(t *testing.T) {
		testTracesGRPOptions(t, otlpOptions{Endpoint: "localhost:3232", Insecure: true}, &tcfg)
	})

	tcfg = TracesConfig{
		CommonEndpoint:     "https://localhost:3232",
		InsecureSkipVerify: true,
	}

	t.Run("testing with skip TLS verification", func(t *testing.T) {
		testTracesGRPOptions(t, otlpOptions{Endpoint: "localhost:3232", SkipTLSVerify: true}, &tcfg)
	})
}

func testTracesGRPOptions(t *testing.T, expected otlpOptions, tcfg *TracesConfig) {
	defer restoreEnvAfterExecution()()
	opts, err := getGRPCTracesEndpointOptions(tcfg)
	require.NoError(t, err)
	assert.Equal(t, expected, opts)
}

func TestTracesSetupHTTP_Protocol(t *testing.T) {
	testCases := []struct {
		Endpoint              string
		ProtoVal              Protocol
		TraceProtoVal         Protocol
		ExpectedProtoEnv      string
		ExpectedTraceProtoEnv string
	}{
		{ProtoVal: "", TraceProtoVal: "", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "http/protobuf"},
		{ProtoVal: "", TraceProtoVal: "foo", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "foo"},
		{ProtoVal: "bar", TraceProtoVal: "", ExpectedProtoEnv: "bar", ExpectedTraceProtoEnv: ""},
		{ProtoVal: "bar", TraceProtoVal: "foo", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "foo"},
		{Endpoint: "http://foo:4317", ProtoVal: "", TraceProtoVal: "", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "grpc"},
		{Endpoint: "http://foo:4317", ProtoVal: "", TraceProtoVal: "foo", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "foo"},
		{Endpoint: "http://foo:4317", ProtoVal: "bar", TraceProtoVal: "", ExpectedProtoEnv: "bar", ExpectedTraceProtoEnv: ""},
		{Endpoint: "http://foo:4317", ProtoVal: "bar", TraceProtoVal: "foo", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "foo"},
		{Endpoint: "http://foo:14317", ProtoVal: "", TraceProtoVal: "", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "grpc"},
		{Endpoint: "http://foo:14317", ProtoVal: "", TraceProtoVal: "foo", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "foo"},
		{Endpoint: "http://foo:14317", ProtoVal: "bar", TraceProtoVal: "", ExpectedProtoEnv: "bar", ExpectedTraceProtoEnv: ""},
		{Endpoint: "http://foo:14317", ProtoVal: "bar", TraceProtoVal: "foo", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "foo"},
		{Endpoint: "http://foo:4318", ProtoVal: "", TraceProtoVal: "", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "http/protobuf"},
		{Endpoint: "http://foo:4318", ProtoVal: "", TraceProtoVal: "foo", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "foo"},
		{Endpoint: "http://foo:4318", ProtoVal: "bar", TraceProtoVal: "", ExpectedProtoEnv: "bar", ExpectedTraceProtoEnv: ""},
		{Endpoint: "http://foo:4318", ProtoVal: "bar", TraceProtoVal: "foo", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "foo"},
		{Endpoint: "http://foo:24318", ProtoVal: "", TraceProtoVal: "", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "http/protobuf"},
		{Endpoint: "http://foo:24318", ProtoVal: "", TraceProtoVal: "foo", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "foo"},
		{Endpoint: "http://foo:24318", ProtoVal: "bar", TraceProtoVal: "", ExpectedProtoEnv: "bar", ExpectedTraceProtoEnv: ""},
		{Endpoint: "http://foo:24318", ProtoVal: "bar", TraceProtoVal: "foo", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "foo"},
	}
	for _, tc := range testCases {
		t.Run(tc.Endpoint+"/"+string(tc.ProtoVal)+"/"+string(tc.TraceProtoVal), func(t *testing.T) {
			defer restoreEnvAfterExecution()()
			_, err := getHTTPTracesEndpointOptions(&TracesConfig{
				CommonEndpoint: "http://host:3333",
				TracesEndpoint: tc.Endpoint,
				Protocol:       tc.ProtoVal,
				TracesProtocol: tc.TraceProtoVal,
				SamplingRatio:  1.0,
			})
			require.NoError(t, err)
			assert.Equal(t, tc.ExpectedProtoEnv, os.Getenv(envProtocol))
			assert.Equal(t, tc.ExpectedTraceProtoEnv, os.Getenv(envTracesProtocol))
		})
	}
}

func TestTracesSetupHTTP_DoNotOverrideEnv(t *testing.T) {
	defer restoreEnvAfterExecution()()
	t.Run("setting both variables", func(t *testing.T) {
		defer restoreEnvAfterExecution()()
		require.NoError(t, os.Setenv(envProtocol, "foo-proto"))
		require.NoError(t, os.Setenv(envTracesProtocol, "bar-proto"))
		_, err := getHTTPTracesEndpointOptions(&TracesConfig{
			CommonEndpoint: "http://host:3333",
			Protocol:       "foo",
			TracesProtocol: "bar",
			SamplingRatio:  1.0,
		})
		require.NoError(t, err)
		assert.Equal(t, "foo-proto", os.Getenv(envProtocol))
		assert.Equal(t, "bar-proto", os.Getenv(envTracesProtocol))
	})
	t.Run("setting only proto env var", func(t *testing.T) {
		defer restoreEnvAfterExecution()()
		require.NoError(t, os.Setenv(envProtocol, "foo-proto"))
		_, err := getHTTPTracesEndpointOptions(&TracesConfig{
			CommonEndpoint: "http://host:3333",
			Protocol:       "foo",
			SamplingRatio:  1.0,
		})
		require.NoError(t, err)
		_, ok := os.LookupEnv(envTracesProtocol)
		assert.False(t, ok)
		assert.Equal(t, "foo-proto", os.Getenv(envProtocol))
	})
}

func TestTraces_InternalInstrumentation(t *testing.T) {
	defer restoreEnvAfterExecution()()
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
	inputNode := node.AsStart(func(out chan<- []request.Span) {
		// on every send data signal, the traces generator sends a dummy trace
		for range sendData {
			out <- []request.Span{{Type: request.EventTypeHTTP}}
		}
	})
	internalTraces := &fakeInternalTraces{}
	exporter, err := ReportTraces(context.Background(),
		&TracesConfig{
			CommonEndpoint:    coll.URL,
			BatchTimeout:      10 * time.Millisecond,
			ExportTimeout:     5 * time.Second,
			SamplingRatio:     1.0,
			ReportersCacheLen: 16,
		},
		&global.ContextInfo{
			Metrics: internalTraces,
		})
	require.NoError(t, err)
	inputNode.SendTo(node.AsTerminal(exporter))

	go inputNode.Start()

	sendData <- struct{}{}
	var previousSum, previousCount int
	test.Eventually(t, timeout, func(t require.TestingT) {
		// we can't guarantee the number of calls at test time, but they must be at least 1
		previousSum, previousCount = internalTraces.SumCount()
		assert.LessOrEqual(t, 1, previousSum)
		assert.LessOrEqual(t, 1, previousCount)
		// the sum of metrics should be larger or equal than the number of calls (1 call : n metrics)
		assert.LessOrEqual(t, previousCount, previousSum)
		// no call should return error
		assert.Empty(t, internalTraces.Errors())
	})

	sendData <- struct{}{}
	// after some time, the number of calls should be higher than before
	test.Eventually(t, timeout, func(t require.TestingT) {
		sum, count := internalTraces.SumCount()
		assert.LessOrEqual(t, previousSum, sum)
		assert.LessOrEqual(t, previousCount, count)
		assert.LessOrEqual(t, count, sum)
		// no call should return error
		assert.Zero(t, internalTraces.Errors())
	})

	// collector starts failing, so errors should be received
	coll.CloseClientConnections()
	coll.Close()
	// Wait for the HTTP server to be stopped
	test.Eventually(t, timeout, func(t require.TestingT) {
		_, err := coll.Client().Get(coll.URL + "/foo")
		require.Error(t, err)
	})

	var previousErrCount int
	sendData <- struct{}{}
	test.Eventually(t, timeout, func(t require.TestingT) {
		previousSum, previousCount = internalTraces.SumCount()
		// calls should start returning errors
		previousErrCount = internalTraces.Errors()
		assert.NotZero(t, previousErrCount)
	})

	// after a while, metrics sum should not increase but errors do
	sendData <- struct{}{}
	test.Eventually(t, timeout, func(t require.TestingT) {
		sum, count := internalTraces.SumCount()
		assert.Equal(t, previousSum, sum)
		assert.Equal(t, previousCount, count)
		assert.Less(t, previousErrCount, internalTraces.Errors())
	})
}

func TestTraces_InternalInstrumentationSampling(t *testing.T) {
	defer restoreEnvAfterExecution()()
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
	inputNode := node.AsStart(func(out chan<- []request.Span) {
		// on every send data signal, the traces generator sends a dummy trace
		for range sendData {
			out <- []request.Span{{Type: request.EventTypeHTTP}}
		}
	})
	internalTraces := &fakeInternalTraces{}
	exporter, err := ReportTraces(context.Background(),
		&TracesConfig{
			CommonEndpoint:    coll.URL,
			BatchTimeout:      10 * time.Millisecond,
			ExportTimeout:     5 * time.Second,
			SamplingRatio:     0.0, // sampling 0 means we won't generate any samples
			ReportersCacheLen: 16,
		},
		&global.ContextInfo{
			Metrics: internalTraces,
		})
	require.NoError(t, err)
	inputNode.SendTo(node.AsTerminal(exporter))

	go inputNode.Start()

	// Let's make 10 traces, none should be seen
	for i := 0; i < 10; i++ {
		sendData <- struct{}{}
	}
	var previousSum, previousCount int
	test.Eventually(t, timeout, func(t require.TestingT) {
		// we shouldn't see any data
		previousSum, previousCount = internalTraces.SumCount()
		assert.Equal(t, 0, previousSum)
		assert.Equal(t, 0, previousCount)
		// no call should return error
		assert.Empty(t, internalTraces.Errors())
	})
}

type fakeInternalTraces struct {
	imetrics.NoopReporter
	sum  atomic.Int32
	cnt  atomic.Int32
	errs atomic.Int32
}

func (f *fakeInternalTraces) OTELTraceExport(len int) {
	f.cnt.Add(1)
	f.sum.Add(int32(len))
}

func (f *fakeInternalTraces) OTELTraceExportError(_ error) {
	f.errs.Add(1)
}

func (f *fakeInternalTraces) Errors() int {
	return int(f.errs.Load())
}

func (f *fakeInternalTraces) SumCount() (sum, count int) {
	return int(f.sum.Load()), int(f.cnt.Load())
}

// stores the values of some modified env vars to avoid
// interferences between cases. Must be invoked as:
// defer restoreEnvAfterExecution()()
func restoreEnvAfterExecution() func() {
	vals := []*struct {
		name   string
		val    string
		exists bool
	}{
		{name: envTracesProtocol}, {name: envMetricsProtocol}, {name: envProtocol},
	}
	for _, v := range vals {
		v.val, v.exists = os.LookupEnv(v.name)
	}
	return func() {
		for _, v := range vals {
			if v.exists {
				os.Setenv(v.name, v.val)
			} else {
				os.Unsetenv(v.name)
			}
		}
	}
}

func TestTraces_Traceparent(t *testing.T) {
	type traceparentTest struct {
		badTid bool
		badPid bool
		tp     [55]byte
	}

	// Traceparents are byte arrays here, like what is provided by eBPF.
	testTraceparents := []traceparentTest{
		{badTid: false, badPid: false, tp: [55]byte([]byte("00-fe211fdbe7577019574171229dc11c68-0795b6fd135d1cad-01"))},
		{badTid: false, badPid: false, tp: [55]byte([]byte("00-fe211fdbe7577019574171229dc11c68-0795b6fd135d1cad-00"))},
		{badTid: false, badPid: false, tp: [55]byte([]byte("00-4fa876be53b9e76974dc030d4cf346ea-2620fa5719017438-01"))},
		{badTid: false, badPid: false, tp: [55]byte([]byte("00-4fa876be53b9e76974dc030d4cf346ea-2620fa5719017438-00"))},
		{badTid: false, badPid: false, tp: [55]byte([]byte("00-55b136efe14761a763df0779a2e4c057-0fb91de9e2199abe-01"))},
		{badTid: false, badPid: false, tp: [55]byte([]byte("00-55b136efe14761a763df0779a2e4c057-0fb91de9e2199abe-00"))},
		{badTid: false, badPid: false, tp: [55]byte([]byte("00-55b136efe14761a763df0779a2e4c057-0fb91de9e2199abe-0x"))},
		{badTid: false, badPid: false, tp: [55]byte([]byte("00-55b136efe14761a763df0779a2e4c057-0fb91de9e2199abe-gg"))},
		{badTid: true, badPid: true, tp: [55]byte{'\r', '\n'}},
		{badTid: true, badPid: true, tp: [55]byte{0}},
		{badTid: true, badPid: true, tp: [55]byte{'0'}},
		{badTid: true, badPid: true, tp: [55]byte{'0', '0', '-'}},
		{badTid: true, badPid: false, tp: [55]byte([]byte("00-Zfe865607da112abd799ea8108c38bcb-4c59e9a913c480a3-01"))},
		{badTid: true, badPid: false, tp: [55]byte([]byte("00-5fe865607da112abd799ea8108c38bcL-4c59e9a913c480a3-01"))},
		{badTid: true, badPid: false, tp: [55]byte([]byte("00-5fe865607Ra112abd799ea8108c38bcb-4c59e9a913c480a3-01"))},
		{badTid: true, badPid: false, tp: [55]byte([]byte("00-0x5fe865607da112abd799ea8108c3cb-4c59e9a913c480a3-01"))},
		{badTid: true, badPid: false, tp: [55]byte([]byte("00-5FE865607DA112ABD799EA8108C38BCB-4c59e9a913c480a3-01"))},
		{badTid: false, badPid: true, tp: [55]byte([]byte("00-11111111111111111111111111111111-Zc59e9a913c480a3-01"))},
		{badTid: false, badPid: true, tp: [55]byte([]byte("00-22222222222222222222222222222222-4C59E9A913C480A3-01"))},
		{badTid: false, badPid: true, tp: [55]byte([]byte("00-33333333333333333333333333333333-4c59e9aW13c480a3-01"))},
		{badTid: false, badPid: true, tp: [55]byte([]byte("00-44444444444444444444444444444444-4c59e9a9-3c480a3-01"))},
		{badTid: false, badPid: true, tp: [55]byte([]byte("00-55555555555555555555555555555555-0x59e9a913c480a3-01"))},
		{badTid: true, badPid: true, tp: [55]byte([]byte("00-16fddc390bba20bG11ae0ea4e1073735-130c93e94b0x9436-01"))},
		{badTid: true, badPid: false, tp: [55]byte(append([]byte("00-Z8ded37f8a156b0d8b78a861bf0a3b52-0f9b26893b"), []byte{0, 0, 0, 0, 0, 0, 0, 0, 0}...))},
	}
	for _, tpTest := range testTraceparents {
		parentCtx := context.Background()
		originalTraceID := "12345678901234567890123456789012"
		originalParentID := "1122334455667788"

		// Create context with original values to compare afterwards
		traceID, err := trace2.TraceIDFromHex(originalTraceID)
		assert.Nil(t, err)
		parentSpanID, err := trace2.SpanIDFromHex(originalParentID)
		assert.Nil(t, err)
		spanCtx := trace2.SpanContextFromContext(parentCtx).WithTraceID(traceID).WithSpanID(parentSpanID)
		parentCtx = trace2.ContextWithSpanContext(parentCtx, spanCtx)

		t.Log("Testing traceparent:", tpTest.tp)
		parentCtx = handleTraceparentField(parentCtx, string(tpTest.tp[:]))

		if tpTest.badTid {
			assert.Equal(t, traceID, trace2.SpanContextFromContext(parentCtx).TraceID())
		} else {
			assert.NotEqual(t, traceID, trace2.SpanContextFromContext(parentCtx).TraceID())
		}
		if tpTest.badPid {
			assert.Equal(t, parentSpanID, trace2.SpanContextFromContext(parentCtx).SpanID())
		} else {
			if !tpTest.badTid {
				// We only set parent-ID when trace ID is not invalid
				assert.NotEqual(t, parentSpanID, trace2.SpanContextFromContext(parentCtx).SpanID())
			}
		}
	}
}

func TestTraces_HTTPStatus(t *testing.T) {
	type testPair struct {
		httpCode   int
		statusCode codes.Code
	}

	t.Run("HTTP server testing", func(t *testing.T) {
		for _, p := range []testPair{
			{100, codes.Unset},
			{103, codes.Unset},
			{199, codes.Unset},
			{200, codes.Unset},
			{204, codes.Unset},
			{299, codes.Unset},
			{300, codes.Unset},
			{399, codes.Unset},
			{400, codes.Unset},
			{404, codes.Unset},
			{405, codes.Unset},
			{499, codes.Unset},
			{500, codes.Error},
			{5999, codes.Error},
		} {
			assert.Equal(t, p.statusCode, httpSpanStatusCode(&request.Span{Status: p.httpCode, Type: request.EventTypeHTTP}))
			assert.Equal(t, p.statusCode, spanStatusCode(&request.Span{Status: p.httpCode, Type: request.EventTypeHTTP}))
		}
	})

	t.Run("HTTP client testing", func(t *testing.T) {
		for _, p := range []testPair{
			{100, codes.Unset},
			{103, codes.Unset},
			{199, codes.Unset},
			{200, codes.Unset},
			{204, codes.Unset},
			{299, codes.Unset},
			{300, codes.Unset},
			{399, codes.Unset},
			{400, codes.Error},
			{404, codes.Error},
			{405, codes.Error},
			{499, codes.Error},
			{500, codes.Error},
			{5999, codes.Error},
		} {
			assert.Equal(t, p.statusCode, httpSpanStatusCode(&request.Span{Status: p.httpCode, Type: request.EventTypeHTTPClient}))
			assert.Equal(t, p.statusCode, spanStatusCode(&request.Span{Status: p.httpCode, Type: request.EventTypeHTTPClient}))
		}
	})
}

func TestTraces_GRPCStatus(t *testing.T) {
	type testPair struct {
		grpcCode   attribute.KeyValue
		statusCode codes.Code
	}

	t.Run("gRPC server testing", func(t *testing.T) {
		for _, p := range []testPair{
			{semconv.RPCGRPCStatusCodeOk, codes.Unset},
			{semconv.RPCGRPCStatusCodeCancelled, codes.Unset},
			{semconv.RPCGRPCStatusCodeUnknown, codes.Error},
			{semconv.RPCGRPCStatusCodeInvalidArgument, codes.Unset},
			{semconv.RPCGRPCStatusCodeDeadlineExceeded, codes.Error},
			{semconv.RPCGRPCStatusCodeNotFound, codes.Unset},
			{semconv.RPCGRPCStatusCodeAlreadyExists, codes.Unset},
			{semconv.RPCGRPCStatusCodePermissionDenied, codes.Unset},
			{semconv.RPCGRPCStatusCodeResourceExhausted, codes.Unset},
			{semconv.RPCGRPCStatusCodeFailedPrecondition, codes.Unset},
			{semconv.RPCGRPCStatusCodeAborted, codes.Unset},
			{semconv.RPCGRPCStatusCodeOutOfRange, codes.Unset},
			{semconv.RPCGRPCStatusCodeUnimplemented, codes.Error},
			{semconv.RPCGRPCStatusCodeInternal, codes.Error},
			{semconv.RPCGRPCStatusCodeUnavailable, codes.Error},
			{semconv.RPCGRPCStatusCodeDataLoss, codes.Error},
			{semconv.RPCGRPCStatusCodeUnauthenticated, codes.Unset},
		} {
			assert.Equal(t, p.statusCode, grpcSpanStatusCode(&request.Span{Status: int(p.grpcCode.Value.AsInt64()), Type: request.EventTypeGRPC}))
			assert.Equal(t, p.statusCode, spanStatusCode(&request.Span{Status: int(p.grpcCode.Value.AsInt64()), Type: request.EventTypeGRPC}))
		}
	})

	t.Run("gRPC client testing", func(t *testing.T) {
		for _, p := range []testPair{
			{semconv.RPCGRPCStatusCodeOk, codes.Unset},
			{semconv.RPCGRPCStatusCodeCancelled, codes.Error},
			{semconv.RPCGRPCStatusCodeUnknown, codes.Error},
			{semconv.RPCGRPCStatusCodeInvalidArgument, codes.Error},
			{semconv.RPCGRPCStatusCodeDeadlineExceeded, codes.Error},
			{semconv.RPCGRPCStatusCodeNotFound, codes.Error},
			{semconv.RPCGRPCStatusCodeAlreadyExists, codes.Error},
			{semconv.RPCGRPCStatusCodePermissionDenied, codes.Error},
			{semconv.RPCGRPCStatusCodeResourceExhausted, codes.Error},
			{semconv.RPCGRPCStatusCodeFailedPrecondition, codes.Error},
			{semconv.RPCGRPCStatusCodeAborted, codes.Error},
			{semconv.RPCGRPCStatusCodeOutOfRange, codes.Error},
			{semconv.RPCGRPCStatusCodeUnimplemented, codes.Error},
			{semconv.RPCGRPCStatusCodeInternal, codes.Error},
			{semconv.RPCGRPCStatusCodeUnavailable, codes.Error},
			{semconv.RPCGRPCStatusCodeDataLoss, codes.Error},
			{semconv.RPCGRPCStatusCodeUnauthenticated, codes.Error},
		} {
			assert.Equal(t, p.statusCode, grpcSpanStatusCode(&request.Span{Status: int(p.grpcCode.Value.AsInt64()), Type: request.EventTypeGRPCClient}))
			assert.Equal(t, p.statusCode, spanStatusCode(&request.Span{Status: int(p.grpcCode.Value.AsInt64()), Type: request.EventTypeGRPCClient}))
		}
	})
}

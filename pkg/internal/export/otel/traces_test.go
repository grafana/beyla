package otel

import (
	"context"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/mariomac/pipes/pipe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/grafana/beyla/pkg/internal/export/metric"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
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

func TestHTTPTracesWithGrafanaOptions(t *testing.T) {
	defer restoreEnvAfterExecution()
	mcfg := TracesConfig{Grafana: &GrafanaOTLP{
		Submit:     []string{submitMetrics, submitTraces},
		CloudZone:  "eu-west-23",
		InstanceID: "12345",
		APIKey:     "affafafaafkd",
	}}
	t.Run("testing basic Grafana Cloud options", func(t *testing.T) {
		testHTTPTracesOptions(t, otlpOptions{
			Endpoint: "otlp-gateway-eu-west-23.grafana.net",
			URLPath:  "/otlp/v1/traces",
			HTTPHeaders: map[string]string{
				// Basic + output of: echo -n 12345:affafafaafkd | gbase64 -w 0
				"Authorization": "Basic MTIzNDU6YWZmYWZhZmFhZmtk",
			},
		}, &mcfg)
	})
	mcfg.CommonEndpoint = "https://localhost:3939"
	t.Run("Overriding endpoint URL", func(t *testing.T) {
		testHTTPTracesOptions(t, otlpOptions{
			Endpoint: "localhost:3939",
			URLPath:  "/v1/traces",
			HTTPHeaders: map[string]string{
				// Base64 representation of 12345:affafafaafkd
				"Authorization": "Basic MTIzNDU6YWZmYWZhZmFhZmtk",
			},
		}, &mcfg)
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
	opts, err := getHTTPTracesEndpointOptions(&TracesConfig{CommonEndpoint: "http://foo:3030"})
	require.NoError(t, err)
	require.NotEmpty(t, opts)

	_, err = getHTTPTracesEndpointOptions(&TracesConfig{CommonEndpoint: "foo:3030"})
	require.Error(t, err)

	_, err = getHTTPTracesEndpointOptions(&TracesConfig{CommonEndpoint: "foo"})
	require.Error(t, err)
}

func TestGRPCTracesEndpointOptions(t *testing.T) {
	defer restoreEnvAfterExecution()()
	t.Run("do not accept URLs without a scheme", func(t *testing.T) {
		_, err := getGRPCTracesEndpointOptions(&TracesConfig{CommonEndpoint: "foo:3939"})
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
	builder := pipe.NewBuilder(&testPipeline{})
	sendData := make(chan struct{})
	pipe.AddStart(builder, func(impl *testPipeline) *pipe.Start[[]request.Span] {
		return &impl.inputNode
	}, func(out chan<- []request.Span) {
		// on every send data signal, the traces generator sends a dummy trace
		for range sendData {
			out <- []request.Span{{Type: request.EventTypeHTTP}}
		}
	})
	internalTraces := &fakeInternalTraces{}
	pipe.AddFinalProvider(builder, func(impl *testPipeline) *pipe.Final[[]request.Span] {
		return &impl.exporter
	}, ReportTraces(context.Background(),
		&TracesConfig{
			CommonEndpoint:    coll.URL,
			BatchTimeout:      10 * time.Millisecond,
			ExportTimeout:     5 * time.Second,
			ReportersCacheLen: 16,
		},
		&global.ContextInfo{
			Metrics: internalTraces,
		}))
	graph, err := builder.Build()
	require.NoError(t, err)

	graph.Start()

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

	builder := pipe.NewBuilder(&testPipeline{})
	// create a simple dummy graph to send data to the Metrics reporter, which will send
	// metrics to the fake collector
	sendData := make(chan struct{})
	pipe.AddStart(builder, func(impl *testPipeline) *pipe.Start[[]request.Span] {
		return &impl.inputNode
	}, func(out chan<- []request.Span) { // on every send data signal, the traces generator sends a dummy trace
		for range sendData {
			out <- []request.Span{{Type: request.EventTypeHTTP}}
		}
	})
	internalTraces := &fakeInternalTraces{}
	pipe.AddFinalProvider(builder, func(impl *testPipeline) *pipe.Final[[]request.Span] {
		return &impl.exporter
	}, ReportTraces(context.Background(),
		&TracesConfig{
			CommonEndpoint:    coll.URL,
			BatchTimeout:      10 * time.Millisecond,
			ExportTimeout:     5 * time.Second,
			Sampler:           Sampler{Name: "always_off"}, // we won't send any trace
			ReportersCacheLen: 16,
		},
		&global.ContextInfo{
			Metrics: internalTraces,
		}))

	graph, err := builder.Build()
	require.NoError(t, err)

	graph.Start()

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

func TestTracesConfig_Enabled(t *testing.T) {
	assert.True(t, TracesConfig{CommonEndpoint: "foo"}.Enabled())
	assert.True(t, TracesConfig{TracesEndpoint: "foo"}.Enabled())
	assert.True(t, TracesConfig{Grafana: &GrafanaOTLP{Submit: []string{"traces", "metrics"}, InstanceID: "33221"}}.Enabled())
}

func TestTracesConfig_Disabled(t *testing.T) {
	assert.False(t, TracesConfig{}.Enabled())
	assert.False(t, TracesConfig{Grafana: &GrafanaOTLP{Submit: []string{"metrics"}, InstanceID: "33221"}}.Enabled())
	assert.False(t, TracesConfig{Grafana: &GrafanaOTLP{Submit: []string{"traces"}}}.Enabled())
}

func TestTracesIdGenerator(t *testing.T) {
	defer restoreEnvAfterExecution()
	mcfg := TracesConfig{Grafana: &GrafanaOTLP{
		Submit:     []string{submitMetrics, submitTraces},
		CloudZone:  "eu-west-23",
		InstanceID: "12345",
		APIKey:     "affafafaafkd",
	}}
	r := TracesReporter{ctx: context.Background(), cfg: &mcfg}
	r.bsp = sdktrace.NewSimpleSpanProcessor(nil)

	tracers, err := r.newTracers(svc.ID{})
	assert.NoError(t, err)
	assert.NotNil(t, tracers)

	t.Run("testing that we can generate random spans in userspace, if not set by eBPF", func(t *testing.T) {
		_, sp := tracers.tracer.Start(context.Background(), "Test",
			trace.WithTimestamp(time.Now()),
			trace.WithSpanKind(trace.SpanKindServer),
		)
		assert.True(t, sp.SpanContext().HasSpanID())
		assert.True(t, sp.SpanContext().HasTraceID())
	})

	t.Run("testing that we can generate span for fixed parent set eBPF", func(t *testing.T) {
		tID1, spID1 := NewIDs(1)
		assert.True(t, tID1.IsValid())
		assert.True(t, spID1.IsValid())

		parentCtx := trace.ContextWithSpanContext(
			context.Background(),
			trace.SpanContext{}.WithTraceID(tID1).WithSpanID(spID1).WithTraceFlags(trace.FlagsSampled),
		)

		_, sp := tracers.tracer.Start(parentCtx, "Test1",
			trace.WithTimestamp(time.Now()),
			trace.WithSpanKind(trace.SpanKindServer),
		)

		assert.True(t, sp.SpanContext().HasSpanID())
		assert.Equal(t, tID1, sp.SpanContext().TraceID())
		assert.NotEqual(t, spID1, sp.SpanContext().SpanID())

	})

	t.Run("testing that we can generate span for fixed traceID set by eBPF", func(t *testing.T) {
		tID2, spID2 := NewIDs(2)

		parentCtx := ContextWithTrace(context.Background(), tID2)

		_, sp := tracers.tracer.Start(parentCtx, "Test2",
			trace.WithTimestamp(time.Now()),
			trace.WithSpanKind(trace.SpanKindServer),
		)

		assert.True(t, sp.SpanContext().HasSpanID())
		assert.Equal(t, tID2, sp.SpanContext().TraceID())
		assert.NotEqual(t, spID2, sp.SpanContext().SpanID())
	})

	t.Run("testing that we can generate fixed traceID and spanID set by eBPF", func(t *testing.T) {
		tID3, spID3 := NewIDs(3)

		parentCtx := ContextWithTraceParent(context.Background(), tID3, spID3)

		_, sp := tracers.tracer.Start(parentCtx, "Test3",
			trace.WithTimestamp(time.Now()),
			trace.WithSpanKind(trace.SpanKindServer),
		)

		assert.True(t, sp.SpanContext().HasSpanID())
		assert.Equal(t, tID3, sp.SpanContext().TraceID())
		assert.Equal(t, spID3, sp.SpanContext().SpanID())
	})
}

func TestSpanHostPeer(t *testing.T) {
	sp := request.Span{
		HostName: "localhost",
		Host:     "127.0.0.1",
		PeerName: "peerhost",
		Peer:     "127.0.0.2",
	}

	assert.Equal(t, "localhost", metric.SpanHost(&sp))
	assert.Equal(t, "peerhost", metric.SpanPeer(&sp))

	sp = request.Span{
		Host: "127.0.0.1",
		Peer: "127.0.0.2",
	}

	assert.Equal(t, "127.0.0.1", metric.SpanHost(&sp))
	assert.Equal(t, "127.0.0.2", metric.SpanPeer(&sp))

	sp = request.Span{}

	assert.Equal(t, "", metric.SpanHost(&sp))
	assert.Equal(t, "", metric.SpanPeer(&sp))
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
			assert.Equal(t, p.statusCode, SpanStatusCode(&request.Span{Status: p.httpCode, Type: request.EventTypeHTTP}))
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
			assert.Equal(t, p.statusCode, SpanStatusCode(&request.Span{Status: p.httpCode, Type: request.EventTypeHTTPClient}))
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
			assert.Equal(t, p.statusCode, SpanStatusCode(&request.Span{Status: int(p.grpcCode.Value.AsInt64()), Type: request.EventTypeGRPC}))
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
			assert.Equal(t, p.statusCode, SpanStatusCode(&request.Span{Status: int(p.grpcCode.Value.AsInt64()), Type: request.EventTypeGRPCClient}))
		}
	})
}

func NewIDs(counter int) (trace.TraceID, trace.SpanID) {
	var traceID [16]byte
	var spanID [8]byte
	binary.BigEndian.PutUint64(traceID[:8], uint64(counter))
	binary.BigEndian.PutUint64(spanID[:], uint64(counter))

	return trace.TraceID(traceID), trace.SpanID(spanID)
}

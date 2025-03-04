package otel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/mariomac/pipes/pipe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v2/pkg/export/attributes"
	"github.com/grafana/beyla/v2/pkg/export/instrumentations"
	"github.com/grafana/beyla/v2/pkg/internal/imetrics"
	"github.com/grafana/beyla/v2/pkg/internal/pipe/global"
	"github.com/grafana/beyla/v2/pkg/internal/request"
	"github.com/grafana/beyla/v2/pkg/internal/svc"
	"github.com/grafana/beyla/v2/test/collector"
)

var fakeMux = sync.Mutex{}

func TestHTTPMetricsEndpointOptions(t *testing.T) {
	defer restoreEnvAfterExecution()()
	mcfg := MetricsConfig{
		CommonEndpoint:  "https://localhost:3131",
		MetricsEndpoint: "https://localhost:3232/v1/metrics",
		Instrumentations: []string{
			instrumentations.InstrumentationHTTP,
		},
	}

	t.Run("testing with two endpoints", func(t *testing.T) {
		testMetricsHTTPOptions(t, otlpOptions{Endpoint: "localhost:3232", URLPath: "/v1/metrics", Headers: map[string]string{}}, &mcfg)
	})

	mcfg = MetricsConfig{
		CommonEndpoint: "https://localhost:3131/otlp",
		Instrumentations: []string{
			instrumentations.InstrumentationHTTP,
		},
	}

	t.Run("testing with only common endpoint", func(t *testing.T) {
		testMetricsHTTPOptions(t, otlpOptions{Endpoint: "localhost:3131", URLPath: "/otlp/v1/metrics", Headers: map[string]string{}}, &mcfg)
	})

	mcfg = MetricsConfig{
		CommonEndpoint:  "https://localhost:3131",
		MetricsEndpoint: "http://localhost:3232",
		Instrumentations: []string{
			instrumentations.InstrumentationHTTP,
		},
	}
	t.Run("testing with insecure endpoint", func(t *testing.T) {
		testMetricsHTTPOptions(t, otlpOptions{Endpoint: "localhost:3232", Insecure: true, Headers: map[string]string{}}, &mcfg)
	})

	mcfg = MetricsConfig{
		CommonEndpoint:     "https://localhost:3232",
		InsecureSkipVerify: true,
		Instrumentations: []string{
			instrumentations.InstrumentationHTTP,
		},
	}

	t.Run("testing with skip TLS verification", func(t *testing.T) {
		testMetricsHTTPOptions(t, otlpOptions{Endpoint: "localhost:3232", URLPath: "/v1/metrics", SkipTLSVerify: true, Headers: map[string]string{}}, &mcfg)
	})
}

func TestHTTPMetricsWithGrafanaOptions(t *testing.T) {
	defer restoreEnvAfterExecution()
	mcfg := MetricsConfig{Grafana: &GrafanaOTLP{
		Submit:     []string{submitMetrics, submitTraces},
		CloudZone:  "eu-west-23",
		InstanceID: "12345",
		APIKey:     "affafafaafkd",
	}, Instrumentations: []string{instrumentations.InstrumentationHTTP},
	}
	t.Run("testing basic Grafana Cloud options", func(t *testing.T) {
		testMetricsHTTPOptions(t, otlpOptions{
			Endpoint: "otlp-gateway-eu-west-23.grafana.net",
			URLPath:  "/otlp/v1/metrics",
			Headers: map[string]string{
				// Basic + output of: echo -n 12345:affafafaafkd | gbase64 -w 0
				"Authorization": "Basic MTIzNDU6YWZmYWZhZmFhZmtk",
			},
		}, &mcfg)
	})
	mcfg.CommonEndpoint = "https://localhost:3939"
	t.Run("Overriding endpoint URL", func(t *testing.T) {
		testMetricsHTTPOptions(t, otlpOptions{
			Endpoint: "localhost:3939",
			URLPath:  "/v1/metrics",
			Headers: map[string]string{
				// Basic + output of: echo -n 12345:affafafaafkd | gbase64 -w 0
				"Authorization": "Basic MTIzNDU6YWZmYWZhZmFhZmtk",
			},
		}, &mcfg)
	})
}

func testMetricsHTTPOptions(t *testing.T, expected otlpOptions, mcfg *MetricsConfig) {
	defer restoreEnvAfterExecution()()
	opts, err := getHTTPMetricEndpointOptions(mcfg)
	require.NoError(t, err)
	assert.Equal(t, expected, opts)
}

func TestMissingSchemeInMetricsEndpoint(t *testing.T) {
	defer restoreEnvAfterExecution()()
	opts, err := getHTTPMetricEndpointOptions(&MetricsConfig{CommonEndpoint: "http://foo:3030", Instrumentations: []string{instrumentations.InstrumentationHTTP}})
	require.NoError(t, err)
	require.NotEmpty(t, opts)

	_, err = getHTTPMetricEndpointOptions(&MetricsConfig{CommonEndpoint: "foo:3030", Instrumentations: []string{instrumentations.InstrumentationHTTP}})
	require.Error(t, err)

	_, err = getHTTPMetricEndpointOptions(&MetricsConfig{CommonEndpoint: "foo", Instrumentations: []string{instrumentations.InstrumentationHTTP}})
	require.Error(t, err)
}

type testPipeline struct {
	inputNode pipe.Start[[]request.Span]
	exporter  pipe.Final[[]request.Span]
}

func (i *testPipeline) Connect() { i.inputNode.SendTo(i.exporter) }

func TestMetrics_InternalInstrumentation(t *testing.T) {
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

	internalMetrics := &fakeInternalMetrics{}
	pipe.AddFinalProvider(builder, func(impl *testPipeline) *pipe.Final[[]request.Span] {
		return &impl.exporter
	}, ReportMetrics(context.Background(),
		&global.ContextInfo{
			Metrics: internalMetrics,
		},
		&MetricsConfig{CommonEndpoint: coll.URL, Interval: 10 * time.Millisecond, ReportersCacheLen: 16, Features: []string{FeatureApplication}, Instrumentations: []string{instrumentations.InstrumentationHTTP}},
		nil),
	)
	graph, err := builder.Build()
	require.NoError(t, err)

	graph.Start()

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
		assert.Zero(t, internalMetrics.Errors())
	})

	sendData <- struct{}{}
	// after some time, the number of calls should be higher than before
	test.Eventually(t, timeout, func(t require.TestingT) {
		sum, cnt := internalMetrics.SumCount()
		assert.LessOrEqual(t, previousSum, sum)
		assert.LessOrEqual(t, previousCount, cnt)
		assert.Less(t, cnt, sum)
		// no call should return error
		assert.Zero(t, internalMetrics.Errors())
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
		previousSum, previousCount = internalMetrics.SumCount()
		// calls should start returning errors
		previousErrCount = internalMetrics.Errors()
		assert.NotZero(t, previousErrCount)
	})

	// after a while, metrics count should not increase but errors do
	sendData <- struct{}{}
	test.Eventually(t, timeout, func(t require.TestingT) {
		sum, cnt := internalMetrics.SumCount()
		assert.Equal(t, previousSum, sum)
		assert.Equal(t, previousCount, cnt)
		// calls should start returning errors
		assert.Less(t, previousErrCount, internalMetrics.Errors())
	})
}

type fakeInternalMetrics struct {
	imetrics.NoopReporter
	sum  atomic.Int32
	cnt  atomic.Int32
	errs atomic.Int32
}

func TestGRPCMetricsEndpointOptions(t *testing.T) {
	defer restoreEnvAfterExecution()()
	t.Run("do not accept URLs without a scheme", func(t *testing.T) {
		_, err := getGRPCMetricEndpointOptions(&MetricsConfig{CommonEndpoint: "foo:3939"})
		assert.Error(t, err)
	})

	mcfg := MetricsConfig{
		CommonEndpoint:   "https://localhost:3131",
		MetricsEndpoint:  "https://localhost:3232",
		Instrumentations: []string{instrumentations.InstrumentationHTTP},
	}

	t.Run("testing with two endpoints", func(t *testing.T) {
		testMetricsGRPCOptions(t, otlpOptions{Endpoint: "localhost:3232", Headers: map[string]string{}}, &mcfg)
	})

	mcfg = MetricsConfig{
		CommonEndpoint:   "https://localhost:3131",
		Instrumentations: []string{instrumentations.InstrumentationHTTP},
	}

	t.Run("testing with only common endpoint", func(t *testing.T) {
		testMetricsGRPCOptions(t, otlpOptions{Endpoint: "localhost:3131", Headers: map[string]string{}}, &mcfg)
	})

	mcfg = MetricsConfig{
		CommonEndpoint:   "https://localhost:3131",
		MetricsEndpoint:  "http://localhost:3232",
		Instrumentations: []string{instrumentations.InstrumentationHTTP},
	}
	t.Run("testing with insecure endpoint", func(t *testing.T) {
		testMetricsGRPCOptions(t, otlpOptions{Endpoint: "localhost:3232", Insecure: true, Headers: map[string]string{}}, &mcfg)
	})

	mcfg = MetricsConfig{
		CommonEndpoint:     "https://localhost:3232",
		InsecureSkipVerify: true,
		Instrumentations:   []string{instrumentations.InstrumentationHTTP},
	}

	t.Run("testing with skip TLS verification", func(t *testing.T) {
		testMetricsGRPCOptions(t, otlpOptions{Endpoint: "localhost:3232", SkipTLSVerify: true, Headers: map[string]string{}}, &mcfg)
	})
}

func testMetricsGRPCOptions(t *testing.T, expected otlpOptions, mcfg *MetricsConfig) {
	defer restoreEnvAfterExecution()()
	opts, err := getGRPCMetricEndpointOptions(mcfg)
	require.NoError(t, err)
	assert.Equal(t, expected, opts)
}

func TestMetricsSetupHTTP_Protocol(t *testing.T) {
	testCases := []struct {
		Endpoint               string
		ProtoVal               Protocol
		MetricProtoVal         Protocol
		ExpectedProtoEnv       string
		ExpectedMetricProtoEnv string
	}{
		{ProtoVal: "", MetricProtoVal: "", ExpectedProtoEnv: "", ExpectedMetricProtoEnv: "http/protobuf"},
		{ProtoVal: "", MetricProtoVal: "foo", ExpectedProtoEnv: "", ExpectedMetricProtoEnv: "foo"},
		{ProtoVal: "bar", MetricProtoVal: "", ExpectedProtoEnv: "bar", ExpectedMetricProtoEnv: ""},
		{ProtoVal: "bar", MetricProtoVal: "foo", ExpectedProtoEnv: "", ExpectedMetricProtoEnv: "foo"},
		{Endpoint: "http://foo:4317", ProtoVal: "", MetricProtoVal: "", ExpectedProtoEnv: "", ExpectedMetricProtoEnv: "grpc"},
		{Endpoint: "http://foo:4317", ProtoVal: "", MetricProtoVal: "foo", ExpectedProtoEnv: "", ExpectedMetricProtoEnv: "foo"},
		{Endpoint: "http://foo:4317", ProtoVal: "bar", MetricProtoVal: "", ExpectedProtoEnv: "bar", ExpectedMetricProtoEnv: ""},
		{Endpoint: "http://foo:4317", ProtoVal: "bar", MetricProtoVal: "foo", ExpectedProtoEnv: "", ExpectedMetricProtoEnv: "foo"},
		{Endpoint: "http://foo:14317", ProtoVal: "", MetricProtoVal: "", ExpectedProtoEnv: "", ExpectedMetricProtoEnv: "grpc"},
		{Endpoint: "http://foo:14317", ProtoVal: "", MetricProtoVal: "foo", ExpectedProtoEnv: "", ExpectedMetricProtoEnv: "foo"},
		{Endpoint: "http://foo:14317", ProtoVal: "bar", MetricProtoVal: "", ExpectedProtoEnv: "bar", ExpectedMetricProtoEnv: ""},
		{Endpoint: "http://foo:14317", ProtoVal: "bar", MetricProtoVal: "foo", ExpectedProtoEnv: "", ExpectedMetricProtoEnv: "foo"},
		{Endpoint: "http://foo:4318", ProtoVal: "", MetricProtoVal: "", ExpectedProtoEnv: "", ExpectedMetricProtoEnv: "http/protobuf"},
		{Endpoint: "http://foo:4318", ProtoVal: "", MetricProtoVal: "foo", ExpectedProtoEnv: "", ExpectedMetricProtoEnv: "foo"},
		{Endpoint: "http://foo:4318", ProtoVal: "bar", MetricProtoVal: "", ExpectedProtoEnv: "bar", ExpectedMetricProtoEnv: ""},
		{Endpoint: "http://foo:4318", ProtoVal: "bar", MetricProtoVal: "foo", ExpectedProtoEnv: "", ExpectedMetricProtoEnv: "foo"},
		{Endpoint: "http://foo:24318", ProtoVal: "", MetricProtoVal: "", ExpectedProtoEnv: "", ExpectedMetricProtoEnv: "http/protobuf"},
		{Endpoint: "http://foo:24318", ProtoVal: "", MetricProtoVal: "foo", ExpectedProtoEnv: "", ExpectedMetricProtoEnv: "foo"},
		{Endpoint: "http://foo:24318", ProtoVal: "bar", MetricProtoVal: "", ExpectedProtoEnv: "bar", ExpectedMetricProtoEnv: ""},
		{Endpoint: "http://foo:24318", ProtoVal: "bar", MetricProtoVal: "foo", ExpectedProtoEnv: "", ExpectedMetricProtoEnv: "foo"},
	}
	for _, tc := range testCases {
		t.Run(tc.Endpoint+"/"+string(tc.ProtoVal)+"/"+string(tc.MetricProtoVal), func(t *testing.T) {
			defer restoreEnvAfterExecution()()
			_, err := getHTTPMetricEndpointOptions(&MetricsConfig{
				CommonEndpoint:   "http://host:3333",
				MetricsEndpoint:  tc.Endpoint,
				Protocol:         tc.ProtoVal,
				MetricsProtocol:  tc.MetricProtoVal,
				Instrumentations: []string{instrumentations.InstrumentationHTTP},
			})
			require.NoError(t, err)
			assert.Equal(t, tc.ExpectedProtoEnv, os.Getenv(envProtocol))
			assert.Equal(t, tc.ExpectedMetricProtoEnv, os.Getenv(envMetricsProtocol))
		})
	}
}

func TestMetricSetupHTTP_DoNotOverrideEnv(t *testing.T) {
	t.Run("setting both variables", func(t *testing.T) {
		defer restoreEnvAfterExecution()()
		require.NoError(t, os.Setenv(envProtocol, "foo-proto"))
		require.NoError(t, os.Setenv(envMetricsProtocol, "bar-proto"))
		_, err := getHTTPMetricEndpointOptions(&MetricsConfig{
			CommonEndpoint: "http://host:3333", Protocol: "foo", MetricsProtocol: "bar", Instrumentations: []string{instrumentations.InstrumentationHTTP},
		})
		require.NoError(t, err)
		assert.Equal(t, "foo-proto", os.Getenv(envProtocol))
		assert.Equal(t, "bar-proto", os.Getenv(envMetricsProtocol))
	})
	t.Run("setting only proto env var", func(t *testing.T) {
		defer restoreEnvAfterExecution()()
		require.NoError(t, os.Setenv(envProtocol, "foo-proto"))
		_, err := getHTTPMetricEndpointOptions(&MetricsConfig{
			CommonEndpoint: "http://host:3333", Protocol: "foo", Instrumentations: []string{instrumentations.InstrumentationHTTP},
		})
		require.NoError(t, err)
		_, ok := os.LookupEnv(envMetricsProtocol)
		assert.False(t, ok)
		assert.Equal(t, "foo-proto", os.Getenv(envProtocol))
	})
}

type InstrTest struct {
	name      string
	instr     []string
	expected  []string
	extraColl int
}

func TestAppMetrics_ByInstrumentation(t *testing.T) {
	defer restoreEnvAfterExecution()()

	tests := []InstrTest{
		{
			name:      "all instrumentations",
			instr:     []string{instrumentations.InstrumentationALL},
			extraColl: 2,
			expected: []string{
				"http.server.request.duration",
				"http.client.request.duration",
				"rpc.server.duration",
				"rpc.client.duration",
				"db.client.operation.duration",
				"db.client.operation.duration",
				"db.client.operation.duration",
				"messaging.publish.duration",
				"messaging.process.duration",
			},
		},
		{
			name:      "http only",
			instr:     []string{instrumentations.InstrumentationHTTP},
			extraColl: 2,
			expected: []string{
				"http.server.request.duration",
				"http.client.request.duration",
			},
		},
		{
			name:      "grpc only",
			instr:     []string{instrumentations.InstrumentationGRPC},
			extraColl: 0,
			expected: []string{
				"rpc.server.duration",
				"rpc.client.duration",
			},
		},
		{
			name:      "redis only",
			instr:     []string{instrumentations.InstrumentationRedis},
			extraColl: 0,
			expected: []string{
				"db.client.operation.duration",
				"db.client.operation.duration",
			},
		},
		{
			name:      "sql only",
			instr:     []string{instrumentations.InstrumentationSQL},
			extraColl: 0,
			expected: []string{
				"db.client.operation.duration",
			},
		},
		{
			name:      "kafka only",
			instr:     []string{instrumentations.InstrumentationKafka},
			extraColl: 0,
			expected: []string{
				"messaging.publish.duration",
				"messaging.process.duration",
			},
		},
		{
			name:      "none",
			instr:     nil,
			extraColl: 0,
			expected:  []string{},
		},
		{
			name:      "sql and redis",
			instr:     []string{instrumentations.InstrumentationSQL, instrumentations.InstrumentationRedis},
			extraColl: 0,
			expected: []string{
				"db.client.operation.duration",
				"db.client.operation.duration",
				"db.client.operation.duration",
			},
		},
		{
			name:      "kafka and grpc",
			instr:     []string{instrumentations.InstrumentationGRPC, instrumentations.InstrumentationKafka},
			extraColl: 0,
			expected: []string{
				"rpc.server.duration",
				"rpc.client.duration",
				"messaging.publish.duration",
				"messaging.process.duration",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancelCtx := context.WithCancel(context.Background())
			defer cancelCtx()

			otlp, err := collector.Start(ctx)
			require.NoError(t, err)

			now := syncedClock{now: time.Now()}
			timeNow = now.Now

			otelExporter := makeExporter(ctx, t, tt.instr, otlp)

			require.NoError(t, err)

			metrics := make(chan []request.Span, 20)
			go otelExporter(metrics)

			/* Available event types (defined in span.go):
			EventTypeHTTP
			EventTypeGRPC
			EventTypeHTTPClient
			EventTypeGRPCClient
			EventTypeSQLClient
			EventTypeRedisClient
			EventTypeKafkaClient
			EventTypeRedisServer
			EventTypeKafkaServer
			*/
			// WHEN it receives metrics
			metrics <- []request.Span{
				{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeHTTP, Path: "/foo", RequestStart: 100, End: 200},
				{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeHTTPClient, Path: "/bar", RequestStart: 150, End: 175},
				{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeGRPC, Path: "/foo", RequestStart: 100, End: 200},
				{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeGRPCClient, Path: "/bar", RequestStart: 150, End: 175},
				{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeSQLClient, Path: "SELECT", RequestStart: 150, End: 175},
				{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeRedisClient, Method: "SET", RequestStart: 150, End: 175},
				{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeRedisServer, Method: "GET", RequestStart: 150, End: 175},
				{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeKafkaClient, Method: "publish", RequestStart: 150, End: 175},
				{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeKafkaServer, Method: "process", RequestStart: 150, End: 175},
			}

			// Read the exported metrics, add +extraColl for HTTP size metrics
			res := readNChan(t, otlp.Records(), len(tt.expected)+tt.extraColl, timeout)
			m := []collector.MetricRecord{}
			// skip over the byte size metrics
			for _, r := range res {
				if strings.HasSuffix(r.Name, ".duration") {
					m = append(m, r)
				}
			}
			assert.Equal(t, len(tt.expected), len(m))

			for i := 0; i < len(tt.expected); i++ {
				assert.Equal(t, tt.expected[i], m[i].Name)
			}

			restoreEnvAfterExecution()
		})
	}

}

func TestAppMetrics_ResourceAttributes(t *testing.T) {
	defer restoreEnvAfterExecution()()

	require.NoError(t, os.Setenv(envResourceAttrs, "deployment.environment=production,source=upstream.beyla"))

	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	otlp, err := collector.Start(ctx)
	require.NoError(t, err)

	now := syncedClock{now: time.Now()}
	timeNow = now.Now

	otelExporter := makeExporter(ctx, t, []string{instrumentations.InstrumentationHTTP}, otlp)
	require.NoError(t, err)

	metrics := make(chan []request.Span, 1)
	go otelExporter(metrics)

	metrics <- []request.Span{
		{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeHTTP, Path: "/foo", RequestStart: 100, End: 200},
	}

	res := readNChan(t, otlp.Records(), 1, timeout)
	assert.Len(t, res, 1)
	attributes := res[0].ResourceAttributes
	assert.Equal(t, "production", attributes["deployment.environment"])
	assert.Equal(t, "upstream.beyla", attributes["source"])
}

func TestMetricsConfig_Enabled(t *testing.T) {
	assert.True(t, (&MetricsConfig{Features: []string{FeatureApplication, FeatureNetwork}, CommonEndpoint: "foo"}).Enabled())
	assert.True(t, (&MetricsConfig{Features: []string{FeatureApplication}, MetricsEndpoint: "foo"}).Enabled())
	assert.True(t, (&MetricsConfig{Features: []string{FeatureNetwork, FeatureApplication}, Grafana: &GrafanaOTLP{Submit: []string{"traces", "metrics"}, InstanceID: "33221"}}).Enabled())
	assert.True(t, (&MetricsConfig{MetricsEndpoint: "foo", Features: []string{FeatureNetwork}}).Enabled())
}

func TestMetricsConfig_Disabled(t *testing.T) {
	assert.False(t, (&MetricsConfig{Features: []string{FeatureApplication}}).Enabled())
	assert.False(t, (&MetricsConfig{Features: []string{FeatureApplication}, Grafana: &GrafanaOTLP{Submit: []string{"traces"}, InstanceID: "33221"}}).Enabled())
	assert.False(t, (&MetricsConfig{Features: []string{FeatureApplication}, Grafana: &GrafanaOTLP{Submit: []string{"metrics"}}}).Enabled())
	// application feature is not enabled
	assert.False(t, (&MetricsConfig{CommonEndpoint: "foo"}).Enabled())
	assert.False(t, (&MetricsConfig{Grafana: &GrafanaOTLP{Submit: []string{"traces", "metrics"}, InstanceID: "33221"}}).Enabled())
}

func TestSpanMetricsDiscarded(t *testing.T) {
	mc := MetricsConfig{
		Features: []string{FeatureApplication},
	}
	mr := MetricsReporter{
		cfg: &mc,
	}

	svcNoExport := svc.Attrs{}

	svcExportMetrics := svc.Attrs{}
	svcExportMetrics.SetExportsOTelMetrics()

	svcExportTraces := svc.Attrs{}
	svcExportTraces.SetExportsOTelTraces()

	tests := []struct {
		name      string
		span      request.Span
		discarded bool
	}{
		{
			name:      "Foo span is not filtered",
			span:      request.Span{Service: svcNoExport, Type: request.EventTypeHTTPClient, Method: "GET", Route: "/foo", RequestStart: 100, End: 200},
			discarded: false,
		},
		{
			name:      "/v1/metrics span is filtered",
			span:      request.Span{Service: svcExportMetrics, Type: request.EventTypeHTTPClient, Method: "GET", Route: "/v1/metrics", RequestStart: 100, End: 200},
			discarded: true,
		},
		{
			name:      "/v1/traces span is not filtered",
			span:      request.Span{Service: svcExportTraces, Type: request.EventTypeHTTPClient, Method: "GET", Route: "/v1/traces", RequestStart: 100, End: 200},
			discarded: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.discarded, !otelSpanAccepted(&tt.span, &mr), tt.name)
		})
	}
}

func TestMetricsInterval(t *testing.T) {
	cfg := MetricsConfig{
		OTELIntervalMS: 60_000,
	}
	t.Run("If only OTEL is defined, it uses that value", func(t *testing.T) {
		assert.Equal(t, 60*time.Second, cfg.GetInterval())
	})
	cfg.Interval = 5 * time.Second
	t.Run("Beyla interval takes precedence over OTEL", func(t *testing.T) {
		assert.Equal(t, 5*time.Second, cfg.GetInterval())
	})
}

func (f *fakeInternalMetrics) OTELMetricExport(len int) {
	fakeMux.Lock()
	defer fakeMux.Unlock()
	f.cnt.Add(1)
	f.sum.Add(int32(len))
}

func (f *fakeInternalMetrics) OTELMetricExportError(_ error) {
	fakeMux.Lock()
	defer fakeMux.Unlock()
	f.errs.Add(1)
}

func (f *fakeInternalMetrics) Errors() int {
	fakeMux.Lock()
	defer fakeMux.Unlock()
	return int(f.errs.Load())
}

func (f *fakeInternalMetrics) SumCount() (sum, count int) {
	fakeMux.Lock()
	defer fakeMux.Unlock()
	return int(f.sum.Load()), int(f.cnt.Load())
}

func readNChan(t require.TestingT, inCh <-chan collector.MetricRecord, numRecords int, timeout time.Duration) []collector.MetricRecord {
	records := []collector.MetricRecord{}
	for i := 0; i < numRecords; i++ {
		select {
		case item := <-inCh:
			records = append(records, item)
		case <-time.After(timeout):
			require.Failf(t, "timeout while waiting for event in input channel", "timeout: %s", timeout)
			return records
		}
	}
	return records
}

func makeExporter(ctx context.Context, t *testing.T, instrumentations []string, otlp *collector.TestCollector) pipe.FinalFunc[[]request.Span] {
	otelExporter, err := ReportMetrics(
		ctx,
		&global.ContextInfo{}, &MetricsConfig{
			Interval:          50 * time.Millisecond,
			CommonEndpoint:    otlp.ServerEndpoint,
			MetricsProtocol:   ProtocolHTTPProtobuf,
			Features:          []string{FeatureApplication},
			TTL:               30 * time.Minute,
			ReportersCacheLen: 100,
			Instrumentations:  instrumentations,
		}, attributes.Selection{
			attributes.HTTPServerDuration.Section: attributes.InclusionLists{
				Include: []string{"url.path"},
			},
		})()

	require.NoError(t, err)

	return otelExporter
}

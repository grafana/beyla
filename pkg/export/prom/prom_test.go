package prom

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/connector"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/exec"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/svc"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes"
	attr "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes/names"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/instrumentations"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/swarm"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v2/pkg/export/otel"
	"github.com/grafana/beyla/v2/pkg/internal/pipe/global"
	"github.com/grafana/beyla/v2/pkg/internal/request"
)

const timeout = 3 * time.Second

func TestAppMetricsExpiration(t *testing.T) {
	now := syncedClock{now: time.Now()}
	timeNow = now.Now

	ctx := t.Context()
	openPort, err := test.FreeTCPPort()
	require.NoError(t, err)
	promURL := fmt.Sprintf("http://127.0.0.1:%d/metrics", openPort)

	var g attributes.AttrGroups
	g.Add(attributes.GroupKubernetes)

	// GIVEN a Prometheus Metrics Exporter with a metrics expire time of 3 minutes
	promInput := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(20))
	exporter, err := PrometheusEndpoint(
		&global.ContextInfo{
			Prometheus:            &connector.PrometheusManager{},
			HostID:                "my-host",
			MetricAttributeGroups: g,
		},
		&PrometheusConfig{
			Port:                        openPort,
			Path:                        "/metrics",
			TTL:                         3 * time.Minute,
			SpanMetricsServiceCacheSize: 10,
			Features:                    []string{otel.FeatureApplication},
			Instrumentations:            []string{instrumentations.InstrumentationALL},
		},
		&attributes.SelectorConfig{
			SelectionCfg: attributes.Selection{
				attributes.HTTPServerDuration.Section: attributes.InclusionLists{
					Include: []string{"url_path", "k8s.app.version"},
				},
			},
			ExtraGroupAttributesCfg: map[string][]attr.Name{
				"k8s_app_meta": {"k8s.app.version"},
			},
		},
		promInput,
		processEvents,
	)(ctx)
	require.NoError(t, err)

	go exporter(ctx)

	app := exec.FileInfo{
		Service: svc.Attrs{
			UID: svc.UID{Name: "test-app", Namespace: "default", Instance: "test-app-1"},
		},
		Pid: 1,
	}

	// Send a process event so we make target_info
	processEvents.Send(exec.ProcessEvent{Type: exec.ProcessEventCreated, File: &app})

	// WHEN it receives metrics
	promInput.Send([]request.Span{
		{Type: request.EventTypeHTTP,
			Path: "/foo",
			End:  123 * time.Second.Nanoseconds(),
			Service: svc.Attrs{
				Metadata: map[attr.Name]string{
					"k8s.app.version": "v0.0.1",
				},
			},
		},
		{Type: request.EventTypeHTTP, Path: "/baz", End: 456 * time.Second.Nanoseconds()},
	})

	containsTargetInfo := regexp.MustCompile(`\ntarget_info\{.*host_id="my-host"`)

	// THEN the metrics are exported
	test.Eventually(t, timeout, func(t require.TestingT) {
		exported := getMetrics(t, promURL)
		assert.Contains(t, exported, `http_server_request_duration_seconds_sum{k8s_app_version="v0.0.1",url_path="/foo"} 123`)
		assert.Contains(t, exported, `http_server_request_duration_seconds_sum{k8s_app_version="",url_path="/baz"} 456`)
		assert.Regexp(t, containsTargetInfo, exported)
	})

	// AND WHEN it keeps receiving a subset of the initial metrics during the timeout
	now.Advance(2 * time.Minute)
	// WHEN it receives metrics
	promInput.Send([]request.Span{
		{
			Type: request.EventTypeHTTP,
			Path: "/foo",
			End:  123 * time.Second.Nanoseconds(),
			Service: svc.Attrs{
				Metadata: map[attr.Name]string{
					"k8s.app.version": "v0.0.1",
				},
			},
		},
	})
	now.Advance(2 * time.Minute)

	// THEN THE metrics that have been received during the timeout period are still visible
	var exported string
	test.Eventually(t, timeout, func(t require.TestingT) {
		exported = getMetrics(t, promURL)
		assert.Contains(t, exported, `http_server_request_duration_seconds_sum{k8s_app_version="v0.0.1",url_path="/foo"} 246`)
	})
	// BUT not the metrics that haven't been received during that time
	assert.NotContains(t, exported, `http_server_request_duration_seconds_sum{k8s_app_version="",url_path="/baz"}`)
	assert.Regexp(t, containsTargetInfo, exported)
	now.Advance(2 * time.Minute)

	// AND WHEN the metrics labels that disappeared are received again
	promInput.Send([]request.Span{
		{Type: request.EventTypeHTTP, Path: "/baz", End: 456 * time.Second.Nanoseconds()},
	})
	now.Advance(2 * time.Minute)

	// THEN they are reported again, starting from zero in the case of counters
	test.Eventually(t, timeout, func(t require.TestingT) {
		exported = getMetrics(t, promURL)
		assert.Contains(t, exported, `http_server_request_duration_seconds_sum{k8s_app_version="",url_path="/baz"} 456`)
	})
	assert.NotContains(t, exported, `http_server_request_duration_seconds_sum{k8s_app_version="",url_path="/foo"}`)
	assert.Regexp(t, containsTargetInfo, exported)
}

type InstrTest struct {
	name       string
	instr      []string
	expected   []string
	unexpected []string
}

func TestAppMetrics_ByInstrumentation(t *testing.T) {
	tests := []InstrTest{
		{
			name:  "all instrumentations",
			instr: []string{instrumentations.InstrumentationALL},
			expected: []string{
				"http_server_request_duration_seconds",
				"http_client_request_duration_seconds",
				"rpc_server_duration_seconds",
				"rpc_client_duration_seconds",
				"db_client_operation_duration_seconds",
				"messaging_publish_duration_seconds",
				"messaging_process_duration_seconds",
			},
			unexpected: []string{},
		},
		{
			name:  "http only",
			instr: []string{instrumentations.InstrumentationHTTP},
			expected: []string{
				"http_server_request_duration_seconds",
				"http_client_request_duration_seconds",
			},
			unexpected: []string{
				"rpc_server_duration_seconds",
				"rpc_client_duration_seconds",
				"db_client_operation_duration_seconds",
				"messaging_publish_duration_seconds",
				"messaging_process_duration_seconds",
			},
		},
		{
			name:  "grpc only",
			instr: []string{instrumentations.InstrumentationGRPC},
			expected: []string{
				"rpc_server_duration_seconds",
				"rpc_client_duration_seconds",
			},
			unexpected: []string{
				"http_server_request_duration_seconds",
				"http_client_request_duration_seconds",
				"db_client_operation_duration_seconds",
				"messaging_publish_duration_seconds",
				"messaging_process_duration_seconds",
			},
		},
		{
			name:  "redis only",
			instr: []string{instrumentations.InstrumentationRedis},
			expected: []string{
				"db_client_operation_duration_seconds",
				"db_client_operation_duration_seconds",
			},
			unexpected: []string{
				"http_server_request_duration_seconds",
				"http_client_request_duration_seconds",
				"rpc_server_duration_seconds",
				"rpc_client_duration_seconds",
				"messaging_publish_duration_seconds",
				"messaging_process_duration_seconds",
			},
		},
		{
			name:  "sql only",
			instr: []string{instrumentations.InstrumentationSQL},
			expected: []string{
				"db_client_operation_duration_seconds",
			},
			unexpected: []string{
				"http_server_request_duration_seconds",
				"http_client_request_duration_seconds",
				"rpc_server_duration_seconds",
				"rpc_client_duration_seconds",
				"messaging_publish_duration_seconds",
				"messaging_process_duration_seconds",
			},
		},
		{
			name:  "kafka only",
			instr: []string{instrumentations.InstrumentationKafka},
			expected: []string{
				"messaging_publish_duration_seconds",
				"messaging_process_duration_seconds",
			},
			unexpected: []string{
				"http_server_request_duration_seconds",
				"http_client_request_duration_seconds",
				"rpc_server_duration_seconds",
				"rpc_client_duration_seconds",
				"db_client_operation_duration_seconds",
			},
		},
		{
			name:     "none",
			instr:    nil,
			expected: []string{},
			unexpected: []string{
				"http_server_request_duration_seconds",
				"http_client_request_duration_seconds",
				"rpc_server_duration_seconds",
				"rpc_client_duration_seconds",
				"db_client_operation_duration_seconds",
				"messaging_publish_duration_seconds",
				"messaging_process_duration_seconds",
			},
		},
		{
			name:  "sql and redis",
			instr: []string{instrumentations.InstrumentationSQL, instrumentations.InstrumentationRedis},
			expected: []string{
				"db_client_operation_duration_seconds",
			},
			unexpected: []string{
				"http_server_request_duration_seconds",
				"http_client_request_duration_seconds",
				"rpc_server_duration_seconds",
				"rpc_client_duration_seconds",
				"messaging_publish_duration_seconds",
				"messaging_process_duration_seconds",
			},
		},
		{
			name:  "kafka and grpc",
			instr: []string{instrumentations.InstrumentationGRPC, instrumentations.InstrumentationKafka},
			expected: []string{
				"rpc_server_duration_seconds",
				"rpc_client_duration_seconds",
				"messaging_publish_duration_seconds",
				"messaging_process_duration_seconds",
			},
			unexpected: []string{
				"http_server_request_duration_seconds",
				"http_client_request_duration_seconds",
				"db_client_operation_duration_seconds",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := syncedClock{now: time.Now()}
			timeNow = now.Now

			ctx := t.Context()
			openPort, err := test.FreeTCPPort()
			require.NoError(t, err)
			promURL := fmt.Sprintf("http://127.0.0.1:%d/metrics", openPort)

			promInput := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
			exporter := makePromExporter(ctx, t, tt.instr, openPort, promInput)
			go exporter(ctx)

			promInput.Send([]request.Span{
				{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeHTTP, Path: "/foo", RequestStart: 100, End: 200},
				{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeHTTPClient, Path: "/bar", RequestStart: 150, End: 175},
				{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeGRPC, Path: "/foo", RequestStart: 100, End: 200},
				{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeGRPCClient, Path: "/bar", RequestStart: 150, End: 175},
				{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeSQLClient, Path: "SELECT", RequestStart: 150, End: 175},
				{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeRedisClient, Method: "SET", RequestStart: 150, End: 175},
				{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeRedisServer, Method: "GET", RequestStart: 150, End: 175},
				{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeKafkaClient, Method: "publish", RequestStart: 150, End: 175},
				{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeKafkaServer, Method: "process", RequestStart: 150, End: 175},
			})

			var exported string
			test.Eventually(t, timeout, func(t require.TestingT) {
				exported = getMetrics(t, promURL)
				for i := 0; i < len(tt.expected); i++ {
					assert.Contains(t, exported, tt.expected[i])
				}
				for i := 0; i < len(tt.unexpected); i++ {
					assert.NotContains(t, exported, tt.unexpected[i])
				}
			})

		})
	}
}

func TestSpanMetricsDiscarded(t *testing.T) {
	mc := PrometheusConfig{
		Features: []string{otel.FeatureApplication},
	}
	mr := metricsReporter{
		cfg: &mc,
	}

	svcNoExport := svc.Attrs{}

	svcExportMetrics := svc.Attrs{}
	svcExportMetrics.SetExportsOTelMetrics()

	svcExportTraces := svc.Attrs{}
	svcExportTraces.SetExportsOTelTraces()

	ignoredSpan := request.Span{Service: svcExportTraces, Type: request.EventTypeHTTPClient, Method: "GET", Route: "/v1/traces", RequestStart: 100, End: 200}
	ignoredSpan.SetIgnoreMetrics()

	tests := []struct {
		name      string
		span      request.Span
		discarded bool
		filtered  bool
	}{
		{
			name:      "Foo span is not filtered",
			span:      request.Span{Service: svcNoExport, Type: request.EventTypeHTTPClient, Method: "GET", Route: "/foo", RequestStart: 100, End: 200},
			discarded: false,
			filtered:  false,
		},
		{
			name:      "/v1/metrics span is filtered",
			span:      request.Span{Service: svcExportMetrics, Type: request.EventTypeHTTPClient, Method: "GET", Route: "/v1/metrics", RequestStart: 100, End: 200},
			discarded: true,
			filtered:  false,
		},
		{
			name:      "/v1/traces span is filtered because we ignore this span",
			span:      ignoredSpan,
			discarded: false,
			filtered:  true,
		},
		{
			name:      "/v1/traces span is not filtered",
			span:      request.Span{Service: svcExportTraces, Type: request.EventTypeHTTPClient, Method: "GET", Route: "/v1/traces", RequestStart: 100, End: 200},
			discarded: false,
			filtered:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.discarded, !mr.otelSpanObserved(&tt.span), tt.name)
			assert.Equal(t, tt.filtered, mr.otelSpanFiltered(&tt.span), tt.name)
		})
	}
}

func TestTerminatesOnBadPromPort(t *testing.T) {
	now := syncedClock{now: time.Now()}
	timeNow = now.Now

	ctx := t.Context()
	openPort, err := test.FreeTCPPort()
	require.NoError(t, err)

	// Grab the port we just allocated for something else
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, %v, http: %v\n", r.URL.Path, r.TLS == nil)
	})
	server := http.Server{Addr: fmt.Sprintf(":%d", openPort), Handler: handler}
	serverUp := make(chan bool, 1)

	go func() {
		go func() {
			time.Sleep(5 * time.Second)
			serverUp <- true
		}()
		err := server.ListenAndServe()
		fmt.Printf("Terminating server %v\n", err)
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT)

	pm := connector.PrometheusManager{}

	c := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: TracesTargetInfo,
		Help: "target service information in trace span metric format",
	}, []string{"a"}).MetricVec

	pm.Register(openPort, "/metrics", c)
	go pm.StartHTTP(ctx)

	var ok bool
	select {
	case sig := <-sigChan:
		assert.Equal(t, sig, syscall.SIGINT)
		ok = true
	case <-time.After(5 * time.Second):
		ok = false
	}

	assert.True(t, ok)
}

func TestProcessPIDEvents(t *testing.T) {
	mc := PrometheusConfig{
		Features: []string{otel.FeatureApplication},
	}
	mr := metricsReporter{
		cfg:         &mc,
		serviceMap:  map[svc.UID]svc.Attrs{},
		pidsTracker: otel.NewPidServiceTracker(),
	}

	svcA := svc.Attrs{
		UID: svc.UID{Name: "A", Instance: "A"},
	}
	svcB := svc.Attrs{
		UID: svc.UID{Name: "B", Instance: "B"},
	}

	mr.setupPIDToServiceRelationship(1, svcA.UID)
	mr.setupPIDToServiceRelationship(2, svcA.UID)
	mr.setupPIDToServiceRelationship(3, svcB.UID)
	mr.setupPIDToServiceRelationship(4, svcB.UID)

	deleted, uid := mr.disassociatePIDFromService(1)
	assert.Equal(t, false, deleted)
	assert.Equal(t, svc.UID{}, uid)

	deleted, uid = mr.disassociatePIDFromService(1)
	assert.Equal(t, false, deleted)
	assert.Equal(t, svc.UID{}, uid)

	deleted, uid = mr.disassociatePIDFromService(2)
	assert.Equal(t, true, deleted)
	assert.Equal(t, svcA.UID, uid)

	deleted, uid = mr.disassociatePIDFromService(3)
	assert.Equal(t, false, deleted)
	assert.Equal(t, svc.UID{}, uid)

	deleted, uid = mr.disassociatePIDFromService(4)
	assert.Equal(t, true, deleted)
	assert.Equal(t, svcB.UID, uid)
}

var mmux = sync.Mutex{}

func getMetrics(t require.TestingT, promURL string) string {
	mmux.Lock()
	defer mmux.Unlock()
	resp, err := http.Get(promURL)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(body)
}

type syncedClock struct {
	mt  sync.Mutex
	now time.Time
}

func (c *syncedClock) Now() time.Time {
	c.mt.Lock()
	defer c.mt.Unlock()
	return c.now
}

func (c *syncedClock) Advance(t time.Duration) {
	c.mt.Lock()
	defer c.mt.Unlock()
	c.now = c.now.Add(t)
}

func makePromExporter(
	ctx context.Context, t *testing.T, instrumentations []string, openPort int,
	input *msg.Queue[[]request.Span],
) swarm.RunFunc {
	processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(20))
	exporter, err := PrometheusEndpoint(
		&global.ContextInfo{Prometheus: &connector.PrometheusManager{}},
		&PrometheusConfig{
			Port:                        openPort,
			Path:                        "/metrics",
			TTL:                         300 * time.Minute,
			SpanMetricsServiceCacheSize: 10,
			Features:                    []string{otel.FeatureApplication},
			Instrumentations:            instrumentations,
		},
		&attributes.SelectorConfig{
			SelectionCfg: attributes.Selection{
				attributes.HTTPServerDuration.Section: attributes.InclusionLists{
					Include: []string{"url_path"},
				},
			},
		},
		input,
		processEvents,
	)(ctx)
	require.NoError(t, err)

	return exporter
}

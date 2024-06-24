package prom

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/mariomac/pipes/pipe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/pkg/internal/connector"
	"github.com/grafana/beyla/pkg/internal/export/attributes"
	"github.com/grafana/beyla/pkg/internal/export/instrumentations"
	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
)

const timeout = 3 * time.Second

func TestAppMetricsExpiration(t *testing.T) {
	now := syncedClock{now: time.Now()}
	timeNow = now.Now

	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()
	openPort, err := test.FreeTCPPort()
	require.NoError(t, err)
	promURL := fmt.Sprintf("http://127.0.0.1:%d/metrics", openPort)

	// GIVEN a Prometheus Metrics Exporter with a metrics expire time of 3 minutes
	exporter, err := PrometheusEndpoint(
		ctx, &global.ContextInfo{Prometheus: &connector.PrometheusManager{}},
		&PrometheusConfig{
			Port:                        openPort,
			Path:                        "/metrics",
			TTL:                         3 * time.Minute,
			SpanMetricsServiceCacheSize: 10,
			Features:                    []string{otel.FeatureApplication},
			Instrumentations:            []string{instrumentations.InstrumentationALL},
		},
		attributes.Selection{
			attributes.HTTPServerDuration.Section: attributes.InclusionLists{
				Include: []string{"url_path"},
			},
		},
	)()
	require.NoError(t, err)

	metrics := make(chan []request.Span, 20)
	go exporter(metrics)

	time.Sleep(5 * time.Second)

	// WHEN it receives metrics
	metrics <- []request.Span{
		{Type: request.EventTypeHTTP, Path: "/foo", End: 123 * time.Second.Nanoseconds()},
		{Type: request.EventTypeHTTP, Path: "/baz", End: 456 * time.Second.Nanoseconds()},
	}

	// THEN the metrics are exported
	test.Eventually(t, timeout, func(t require.TestingT) {
		exported := getMetrics(t, promURL)
		assert.Contains(t, exported, `http_server_request_duration_seconds_sum{url_path="/foo"} 123`)
		assert.Contains(t, exported, `http_server_request_duration_seconds_sum{url_path="/baz"} 456`)
	})

	// AND WHEN it keeps receiving a subset of the initial metrics during the timeout
	now.Advance(2 * time.Minute)
	// WHEN it receives metrics
	metrics <- []request.Span{
		{Type: request.EventTypeHTTP, Path: "/foo", End: 123 * time.Second.Nanoseconds()},
	}
	now.Advance(2 * time.Minute)

	// THEN THE metrics that have been received during the timeout period are still visible
	var exported string
	test.Eventually(t, timeout, func(t require.TestingT) {
		exported = getMetrics(t, promURL)
		assert.Contains(t, exported, `http_server_request_duration_seconds_sum{url_path="/foo"} 246`)
	})
	// BUT not the metrics that haven't been received during that time
	assert.NotContains(t, exported, `http_server_request_duration_seconds_sum{url_path="/baz"}`)
	now.Advance(2 * time.Minute)

	// AND WHEN the metrics labels that disappeared are received again
	metrics <- []request.Span{
		{Type: request.EventTypeHTTP, Path: "/baz", End: 456 * time.Second.Nanoseconds()},
	}
	now.Advance(2 * time.Minute)

	// THEN they are reported again, starting from zero in the case of counters
	test.Eventually(t, timeout, func(t require.TestingT) {
		exported = getMetrics(t, promURL)
		assert.Contains(t, exported, `http_server_request_duration_seconds_sum{url_path="/baz"} 456`)
	})
	assert.NotContains(t, exported, `http_server_request_duration_seconds_sum{url_path="/foo"}`)
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

			ctx, cancelCtx := context.WithCancel(context.Background())
			defer cancelCtx()
			openPort, err := test.FreeTCPPort()
			require.NoError(t, err)
			promURL := fmt.Sprintf("http://127.0.0.1:%d/metrics", openPort)

			exporter := makePromExporter(ctx, t, tt.instr, openPort)

			metrics := make(chan []request.Span, 20)
			go exporter(metrics)

			metrics <- []request.Span{
				{ServiceID: svc.ID{UID: "foo"}, Type: request.EventTypeHTTP, Path: "/foo", RequestStart: 100, End: 200},
				{ServiceID: svc.ID{UID: "foo"}, Type: request.EventTypeHTTPClient, Path: "/bar", RequestStart: 150, End: 175},
				{ServiceID: svc.ID{UID: "foo"}, Type: request.EventTypeGRPC, Path: "/foo", RequestStart: 100, End: 200},
				{ServiceID: svc.ID{UID: "foo"}, Type: request.EventTypeGRPCClient, Path: "/bar", RequestStart: 150, End: 175},
				{ServiceID: svc.ID{UID: "foo"}, Type: request.EventTypeSQLClient, Path: "SELECT", RequestStart: 150, End: 175},
				{ServiceID: svc.ID{UID: "foo"}, Type: request.EventTypeRedisClient, Method: "SET", RequestStart: 150, End: 175},
				{ServiceID: svc.ID{UID: "foo"}, Type: request.EventTypeRedisServer, Method: "GET", RequestStart: 150, End: 175},
				{ServiceID: svc.ID{UID: "foo"}, Type: request.EventTypeKafkaClient, Method: "publish", RequestStart: 150, End: 175},
				{ServiceID: svc.ID{UID: "foo"}, Type: request.EventTypeKafkaServer, Method: "process", RequestStart: 150, End: 175},
			}

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

func makePromExporter(ctx context.Context, t *testing.T, instrumentations []string, openPort int) pipe.FinalFunc[[]request.Span] {
	exporter, err := PrometheusEndpoint(
		ctx, &global.ContextInfo{Prometheus: &connector.PrometheusManager{}},
		&PrometheusConfig{
			Port:                        openPort,
			Path:                        "/metrics",
			TTL:                         300 * time.Minute,
			SpanMetricsServiceCacheSize: 10,
			Features:                    []string{otel.FeatureApplication},
			Instrumentations:            instrumentations,
		},
		attributes.Selection{
			attributes.HTTPServerDuration.Section: attributes.InclusionLists{
				Include: []string{"url_path"},
			},
		},
	)()
	require.NoError(t, err)

	return exporter
}

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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/pkg/internal/connector"
	"github.com/grafana/beyla/pkg/internal/export/metric"
	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/request"
)

const timeout = 30000 * time.Second

func TestMetricsExpiration(t *testing.T) {
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
		},
		metric.Selection{
			metric.HTTPServerDuration.Section: metric.InclusionLists{
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

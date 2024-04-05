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
	"github.com/grafana/beyla/pkg/internal/export/prom"
	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
)

const timeout = 3 * time.Second

func TestMetricsExpiration(t *testing.T) {
	now := syncedClock{now: time.Now()}
	timeNow = now.Now

	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()
	openPort, err := test.FreeTCPPort()
	require.NoError(t, err)
	promURL := fmt.Sprintf("http://127.0.0.1:%d/metrics", openPort)
	require.NoError(t, err)

	// GIVEN a Prometheus Metrics Exporter with a metrics expire time of 3 minutes
	exporter, err := PrometheusEndpoint(
		ctx,
		&PrometheusConfig{Config: &prom.PrometheusConfig{
			Port:       openPort,
			Path:       "/metrics",
			ExpireTime: 3 * time.Minute,
		}, AllowedAttributes: []string{"src_name", "dst_name"}},
		&connector.PrometheusManager{},
	)
	require.NoError(t, err)

	metrics := make(chan []*ebpf.Record, 20)
	go exporter(metrics)

	// WHEN it receives metrics
	metrics <- []*ebpf.Record{
		{Attrs: ebpf.RecordAttrs{SrcName: "foo", DstName: "bar"},
			NetFlowRecordT: ebpf.NetFlowRecordT{Metrics: ebpf.NetFlowMetrics{Bytes: 123}}},
		{Attrs: ebpf.RecordAttrs{SrcName: "baz", DstName: "bae"},
			NetFlowRecordT: ebpf.NetFlowRecordT{Metrics: ebpf.NetFlowMetrics{Bytes: 456}}},
	}

	// THEN the metrics are exported
	test.Eventually(t, timeout, func(t require.TestingT) {
		exported := getMetrics(t, promURL)
		assert.Contains(t, exported, `beyla_network_flow_bytes_total{dst_name="bar",src_name="foo"} 123`)
		assert.Contains(t, exported, `beyla_network_flow_bytes_total{dst_name="bae",src_name="baz"} 456`)
	})

	// AND WHEN it keeps receiving a subset of the initial metrics during the timeout
	now.Advance(2 * time.Minute)
	metrics <- []*ebpf.Record{
		{Attrs: ebpf.RecordAttrs{SrcName: "foo", DstName: "bar"},
			NetFlowRecordT: ebpf.NetFlowRecordT{Metrics: ebpf.NetFlowMetrics{Bytes: 123}}},
	}
	now.Advance(2 * time.Minute)

	// THEN THE metrics that have been received during the timeout period are still visible
	var exported string
	test.Eventually(t, timeout, func(t require.TestingT) {
		exported = getMetrics(t, promURL)
		assert.Contains(t, exported, `beyla_network_flow_bytes_total{dst_name="bar",src_name="foo"} 246`)
	})
	// BUT not the metrics that haven't been received during that time
	assert.NotContains(t, exported, `beyla_network_flow_bytes_total{dst_name="bae",src_name="baz"}`)
	now.Advance(2 * time.Minute)

	// AND WHEN the metrics labels that disappeared are received again
	metrics <- []*ebpf.Record{
		{Attrs: ebpf.RecordAttrs{SrcName: "baz", DstName: "bae"},
			NetFlowRecordT: ebpf.NetFlowRecordT{Metrics: ebpf.NetFlowMetrics{Bytes: 456}}},
	}
	now.Advance(2 * time.Minute)

	// THEN they are reported again, starting from zero in the case of counters
	test.Eventually(t, timeout, func(t require.TestingT) {
		exported = getMetrics(t, promURL)
		assert.Contains(t, exported, `beyla_network_flow_bytes_total{dst_name="bae",src_name="baz"} 456`)
	})
	assert.NotContains(t, exported, `beyla_network_flow_bytes_total{dst_name="bar",src_name="foo"}`)
}

func getMetrics(t require.TestingT, promURL string) string {
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

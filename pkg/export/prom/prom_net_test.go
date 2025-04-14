package prom

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v2/pkg/export/attributes"
	"github.com/grafana/beyla/v2/pkg/export/otel"
	"github.com/grafana/beyla/v2/pkg/internal/connector"
	"github.com/grafana/beyla/v2/pkg/internal/netolly/ebpf"
	"github.com/grafana/beyla/v2/pkg/internal/pipe/global"
	"github.com/grafana/beyla/v2/pkg/pipe/msg"
)

func TestMetricsExpiration(t *testing.T) {
	now := syncedClock{now: time.Now()}
	timeNow = now.Now

	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()
	openPort, err := test.FreeTCPPort()
	require.NoError(t, err)
	promURL := fmt.Sprintf("http://127.0.0.1:%d/metrics", openPort)

	// GIVEN a Prometheus Metrics Exporter with a metrics expire time of 3 minutes
	metrics := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(20))
	exporter, err := NetPrometheusEndpoint(
		&global.ContextInfo{Prometheus: &connector.PrometheusManager{}},
		&NetPrometheusConfig{Config: &PrometheusConfig{
			Port:                        openPort,
			Path:                        "/metrics",
			TTL:                         3 * time.Minute,
			SpanMetricsServiceCacheSize: 10,
			Features:                    []string{otel.FeatureNetwork},
		}, AttributeSelectors: attributes.Selection{
			attributes.BeylaNetworkFlow.Section: attributes.InclusionLists{
				Include: []string{"src_name", "dst_name"},
			},
		}}, metrics)(ctx)
	require.NoError(t, err)

	go exporter(ctx)

	// WHEN it receives metrics
	metrics.Send([]*ebpf.Record{
		{Attrs: ebpf.RecordAttrs{SrcName: "foo", DstName: "bar"},
			NetFlowRecordT: ebpf.NetFlowRecordT{Metrics: ebpf.NetFlowMetrics{Bytes: 123}}},
		{Attrs: ebpf.RecordAttrs{SrcName: "baz", DstName: "bae"},
			NetFlowRecordT: ebpf.NetFlowRecordT{Metrics: ebpf.NetFlowMetrics{Bytes: 456}}},
	})

	// THEN the metrics are exported
	test.Eventually(t, timeout, func(t require.TestingT) {
		exported := getMetrics(t, promURL)
		assert.Contains(t, exported, `beyla_network_flow_bytes_total{dst_name="bar",src_name="foo"} 123`)
		assert.Contains(t, exported, `beyla_network_flow_bytes_total{dst_name="bae",src_name="baz"} 456`)
	})

	// AND WHEN it keeps receiving a subset of the initial metrics during the timeout
	now.Advance(2 * time.Minute)
	metrics.Send([]*ebpf.Record{
		{Attrs: ebpf.RecordAttrs{SrcName: "foo", DstName: "bar"},
			NetFlowRecordT: ebpf.NetFlowRecordT{Metrics: ebpf.NetFlowMetrics{Bytes: 123}}},
	})
	now.Advance(2 * time.Minute)

	// THEN THE metrics that have been received during the timeout period are still visible
	var exported string
	test.Eventually(t, timeout, func(t require.TestingT) {
		m := getMetrics(t, promURL)
		assert.Contains(t, exported, `beyla_network_flow_bytes_total{dst_name="bar",src_name="foo"} 246`)
		exported = m
	})
	// BUT not the metrics that haven't been received during that time
	assert.NotContains(t, exported, `beyla_network_flow_bytes_total{dst_name="bae",src_name="baz"}`)
	now.Advance(2 * time.Minute)

	// AND WHEN the metrics labels that disappeared are received again
	metrics.Send([]*ebpf.Record{
		{Attrs: ebpf.RecordAttrs{SrcName: "baz", DstName: "bae"},
			NetFlowRecordT: ebpf.NetFlowRecordT{Metrics: ebpf.NetFlowMetrics{Bytes: 456}}},
	})
	now.Advance(2 * time.Minute)

	// THEN they are reported again, starting from zero in the case of counters
	test.Eventually(t, timeout, func(t require.TestingT) {
		m := getMetrics(t, promURL)
		assert.Contains(t, exported, `beyla_network_flow_bytes_total{dst_name="bae",src_name="baz"} 456`)
		exported = m
	})
	assert.NotContains(t, exported, `beyla_network_flow_bytes_total{dst_name="bar",src_name="foo"}`)
}

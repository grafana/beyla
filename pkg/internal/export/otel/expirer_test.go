package otel

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/pkg/internal/export/attributes"
	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/test/collector"
)

const timeout = 10 * time.Second

func TestMetricsExpiration(t *testing.T) {
	defer restoreEnvAfterExecution()()
	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	otlp, err := collector.Start(ctx)
	require.NoError(t, err)

	now := syncedClock{now: time.Now()}
	timeNow = now.Now

	otelExporter, err := NetMetricsExporterProvider(
		ctx,
		&global.ContextInfo{}, &NetMetricsConfig{
			Metrics: &MetricsConfig{
				Interval:        50 * time.Millisecond,
				CommonEndpoint:  otlp.ServerEndpoint,
				MetricsProtocol: ProtocolHTTPProtobuf,
				Features:        []string{FeatureNetwork},
				TTL:             3 * time.Minute,
			}, AttributeSelectors: attributes.Selection{
				attributes.BeylaNetworkFlow.Section: attributes.InclusionLists{
					Include: []string{"src.name", "dst.name"},
				},
			},
		})
	require.NoError(t, err)

	metrics := make(chan []*ebpf.Record, 20)
	go otelExporter(metrics)

	// WHEN it receives metrics
	metrics <- []*ebpf.Record{
		{Attrs: ebpf.RecordAttrs{SrcName: "foo", DstName: "bar"},
			NetFlowRecordT: ebpf.NetFlowRecordT{Metrics: ebpf.NetFlowMetrics{Bytes: 123}}},
		{Attrs: ebpf.RecordAttrs{SrcName: "baz", DstName: "bae"},
			NetFlowRecordT: ebpf.NetFlowRecordT{Metrics: ebpf.NetFlowMetrics{Bytes: 456}}},
	}

	// THEN the metrics are exported
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records, timeout)
		assert.Equal(t, map[string]string{"src.name": "foo", "dst.name": "bar"}, metric.Attributes)
		assert.EqualValues(t, 123, metric.IntVal)
	})
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records, timeout)
		assert.Equal(t, map[string]string{"src.name": "baz", "dst.name": "bae"}, metric.Attributes)
		assert.EqualValues(t, 456, metric.IntVal)
	})
	// AND WHEN it keeps receiving a subset of the initial metrics during the timeout
	now.Advance(2 * time.Minute)
	metrics <- []*ebpf.Record{
		{Attrs: ebpf.RecordAttrs{SrcName: "foo", DstName: "bar"},
			NetFlowRecordT: ebpf.NetFlowRecordT{Metrics: ebpf.NetFlowMetrics{Bytes: 123}}},
	}
	now.Advance(2 * time.Minute)

	// THEN THE metrics that have been received during the timeout period are still visible
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records, timeout)
		assert.Equal(t, map[string]string{"src.name": "foo", "dst.name": "bar"}, metric.Attributes)
		assert.EqualValues(t, 246, metric.IntVal)
	})

	// BUT not the metrics that haven't been received during that time
	// (we just know it because OTEL just sends a metric with the same value)
	metric := readChan(t, otlp.Records, timeout)
	assert.Equal(t, map[string]string{"src.name": "foo", "dst.name": "bar"}, metric.Attributes)
	assert.EqualValues(t, 246, metric.IntVal)

	now.Advance(2 * time.Minute)

	// AND WHEN the metrics labels that disappeared are received again
	metrics <- []*ebpf.Record{
		{Attrs: ebpf.RecordAttrs{SrcName: "baz", DstName: "bae"},
			NetFlowRecordT: ebpf.NetFlowRecordT{Metrics: ebpf.NetFlowMetrics{Bytes: 456}}},
	}
	now.Advance(2 * time.Minute)

	// THEN they are reported again, starting from zero in the case of counters
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records, timeout)
		assert.Equal(t, map[string]string{"src.name": "baz", "dst.name": "bae"}, metric.Attributes)
		assert.EqualValues(t, 456, metric.IntVal)
	})
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

func readChan(t require.TestingT, inCh <-chan collector.MetricRecord, timeout time.Duration) collector.MetricRecord {
	select {
	case item := <-inCh:
		return item
	case <-time.After(timeout):
		require.Failf(t, "timeout while waiting for event in input channel", "timeout: %s", timeout)
	}
	return collector.MetricRecord{}
}

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
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/test/collector"
)

const timeout = 20 * time.Second

func TestNetMetricsExpiration(t *testing.T) {
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
		metric := readChan(t, otlp.Records(), timeout)
		assert.Equal(t, map[string]string{"src.name": "foo", "dst.name": "bar"}, metric.Attributes)
		assert.EqualValues(t, 123, metric.IntVal)
	})
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records(), timeout)
		assert.Equal(t, map[string]string{"src.name": "baz", "dst.name": "bae"}, metric.Attributes)
		assert.EqualValues(t, 456, metric.IntVal)
	})
	// AND WHEN it keeps receiving a subset of the initial metrics during the TTL
	now.Advance(2 * time.Minute)
	metrics <- []*ebpf.Record{
		{Attrs: ebpf.RecordAttrs{SrcName: "foo", DstName: "bar"},
			NetFlowRecordT: ebpf.NetFlowRecordT{Metrics: ebpf.NetFlowMetrics{Bytes: 123}}},
	}

	// THEN THE metrics that have been received during the TTL period are still visible
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records(), timeout)
		assert.Equal(t, map[string]string{"src.name": "foo", "dst.name": "bar"}, metric.Attributes)
		assert.EqualValues(t, 246, metric.IntVal)
	})

	now.Advance(2 * time.Minute)
	metrics <- []*ebpf.Record{
		{Attrs: ebpf.RecordAttrs{SrcName: "foo", DstName: "bar"},
			NetFlowRecordT: ebpf.NetFlowRecordT{Metrics: ebpf.NetFlowMetrics{Bytes: 123}}},
	}

	// makes sure that the records channel is emptied and any remaining
	// old metric is sent and then the channel is re-emptied
	otlp.ResetRecords()
	readChan(t, otlp.Records(), timeout)
	otlp.ResetRecords()

	// BUT not the metrics that haven't been received during that time.
	// We just know it because OTEL will only sends foo/bar metric.
	// If this test is flaky: it means it is actually failing
	// repeating 10 times to make sure that only this metric is forwarded
	for i := 0; i < 10; i++ {
		metric := readChan(t, otlp.Records(), timeout)
		require.Equal(t, map[string]string{"src.name": "foo", "dst.name": "bar"}, metric.Attributes)
		require.EqualValues(t, 369, metric.IntVal)
	}

	// AND WHEN the metrics labels that disappeared are received again
	now.Advance(2 * time.Minute)
	metrics <- []*ebpf.Record{
		{Attrs: ebpf.RecordAttrs{SrcName: "baz", DstName: "bae"},
			NetFlowRecordT: ebpf.NetFlowRecordT{Metrics: ebpf.NetFlowMetrics{Bytes: 456}}},
	}

	// THEN they are reported again, starting from zero in the case of counters
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records(), timeout)
		assert.Equal(t, map[string]string{"src.name": "baz", "dst.name": "bae"}, metric.Attributes)
		assert.EqualValues(t, 456, metric.IntVal)
	})
}

func TestAppMetricsExpiration(t *testing.T) {
	defer restoreEnvAfterExecution()()
	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	otlp, err := collector.Start(ctx)
	require.NoError(t, err)

	now := syncedClock{now: time.Now()}
	timeNow = now.Now

	otelExporter, err := ReportMetrics(
		ctx,
		&global.ContextInfo{}, &MetricsConfig{
			Interval:          50 * time.Millisecond,
			CommonEndpoint:    otlp.ServerEndpoint,
			MetricsProtocol:   ProtocolHTTPProtobuf,
			Features:          []string{FeatureApplication},
			TTL:               3 * time.Minute,
			ReportersCacheLen: 100,
		}, attributes.Selection{
			attributes.HTTPServerDuration.Section: attributes.InclusionLists{
				Include: []string{"url.path"},
			},
		})()

	require.NoError(t, err)

	metrics := make(chan []request.Span, 20)
	go otelExporter(metrics)

	// WHEN it receives metrics
	metrics <- []request.Span{
		{Type: request.EventTypeHTTP, Path: "/foo", RequestStart: 100, End: 200},
		{Type: request.EventTypeHTTP, Path: "/bar", RequestStart: 150, End: 175},
	}

	// THEN the metrics are exported
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records(), timeout)
		assert.Equal(t, "http.server.request.duration", metric.Name)
		assert.Equal(t, map[string]string{"url.path": "/foo"}, metric.Attributes)
		assert.EqualValues(t, 100/float64(time.Second), metric.FloatVal)
	})

	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records(), timeout)
		require.Equal(t, "http.server.request.duration", metric.Name)
		assert.Equal(t, map[string]string{"url.path": "/bar"}, metric.Attributes)
		assert.EqualValues(t, 25/float64(time.Second), metric.FloatVal)
	})

	// AND WHEN it keeps receiving a subset of the initial metrics during the TTL
	now.Advance(2 * time.Minute)
	metrics <- []request.Span{
		{Type: request.EventTypeHTTP, Path: "/foo", RequestStart: 250, End: 280},
	}

	// THEN THE metrics that have been received during the TTL period are still visible
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records(), timeout)
		require.Equal(t, "http.server.request.duration", metric.Name)
		assert.Equal(t, map[string]string{"url.path": "/foo"}, metric.Attributes)
		assert.EqualValues(t, 130/float64(time.Second), metric.FloatVal)
	})

	now.Advance(2 * time.Minute)
	metrics <- []request.Span{
		{Type: request.EventTypeHTTP, Path: "/foo", RequestStart: 300, End: 310},
	}

	// makes sure that the records channel is emptied and any remaining
	// old metric is sent and then the channel is re-emptied
	otlp.ResetRecords()
	readChan(t, otlp.Records(), timeout)
	otlp.ResetRecords()

	// BUT not the metrics that haven't been received during that time.
	// We just know it because OTEL will only sends foo/bar metric.
	// If this test is flaky: it means it is actually failing
	// repeating 10 times to make sure that only this metric is forwarded
	for i := 0; i < 10; i++ {
		metric := readChan(t, otlp.Records(), timeout)
		if metric.Name != "http.server.request.duration" {
			// ignore other HTTP metrics (e.g. request size)
			i--
			continue
		}
		require.Equal(t, "http.server.request.duration", metric.Name)
		assert.Equal(t, map[string]string{"url.path": "/foo"}, metric.Attributes)
		assert.EqualValues(t, 140/float64(time.Second), metric.FloatVal)
	}

	// AND WHEN the metrics labels that disappeared are received again
	now.Advance(2 * time.Minute)
	metrics <- []request.Span{
		{Type: request.EventTypeHTTP, Path: "/bar", RequestStart: 450, End: 520},
	}

	// THEN they are reported again, starting from zero in the case of counters
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records(), timeout)
		require.Equal(t, "http.server.request.duration", metric.Name)
		assert.Equal(t, map[string]string{"url.path": "/bar"}, metric.Attributes)
		assert.EqualValues(t, 70/float64(time.Second), metric.FloatVal)
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

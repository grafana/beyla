package hostinfo

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/pipe/msg"

	"github.com/grafana/beyla/v3/pkg/export/otel/bexport"
)

type recordingExporter struct {
	output   chan metricdata.ResourceMetrics
	shutdown atomic.Bool
}

func (*recordingExporter) Temporality(sdkmetric.InstrumentKind) metricdata.Temporality {
	return metricdata.CumulativeTemporality
}
func (*recordingExporter) Aggregation(k sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return sdkmetric.DefaultAggregationSelector(k)
}
func (e *recordingExporter) Export(_ context.Context, m *metricdata.ResourceMetrics) error {
	// The SDK can reuse storage after Export returns.
	copy := metricdata.ResourceMetrics{Resource: m.Resource}
	for _, scope := range m.ScopeMetrics {
		out := metricdata.ScopeMetrics{Scope: scope.Scope}
		for _, metric := range scope.Metrics {
			if gauge, ok := metric.Data.(metricdata.Gauge[int64]); ok {
				metric.Data = metricdata.Gauge[int64]{DataPoints: append([]metricdata.DataPoint[int64](nil), gauge.DataPoints...)}
				out.Metrics = append(out.Metrics, metric)
			}
		}
		copy.ScopeMetrics = append(copy.ScopeMetrics, out)
	}
	select {
	case e.output <- copy:
	default:
	}
	return nil
}
func (*recordingExporter) ForceFlush(context.Context) error { return nil }
func (e *recordingExporter) Shutdown(context.Context) error { e.shutdown.Store(true); return nil }

func TestHostInfoBothExporters(t *testing.T) {
	// Given two exporters observing the same spans and process events.
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	input := msg.NewQueue[[]request.Span]()
	events := msg.NewQueue[exec.ProcessEvent]()
	registry := prometheus.NewRegistry()
	exporter := &recordingExporter{output: make(chan metricdata.ResourceMetrics, 100)}

	otelRun, err := OTELExport(OTELConfig{
		HostID: "configured-host", Enabled: true, Interval: 5 * time.Millisecond, TTL: time.Minute,
		Exporter: func(context.Context) (sdkmetric.Exporter, error) { return exporter, nil },
	}, input, events)(ctx)
	require.NoError(t, err)
	promRun, err := PromExport(PromConfig{
		HostID: "configured-host", Enabled: true, TTL: time.Minute, Register: registry.Register,
	}, input, events)(ctx)
	require.NoError(t, err)
	var runners sync.WaitGroup
	runners.Add(2)
	go func() { defer runners.Done(); otelRun(ctx) }()
	go func() { defer runners.Done(); promRun(ctx) }()
	done := make(chan struct{})
	go func() { runners.Wait(); close(done) }()

	// Before any activity, Prometheus has no host-info series.
	families, err := registry.Gather()
	require.NoError(t, err)
	require.Empty(t, families, "no series before eligible activity")

	// When a process emits a span with host-info reporting enabled.
	span := request.Span{Type: request.EventTypeHTTP}
	span.Service.Features = bexport.FeatureHostInfo
	span.Pid.HostPID = 123
	input.Send([]request.Span{span})

	// Then Prometheus reports the gauge with the Grafana host label.
	require.Eventually(t, func() bool {
		families, err = registry.Gather()
		return err == nil && len(families) == 1
	}, time.Second, time.Millisecond)
	require.Equal(t, "traces_host_info", families[0].GetName())
	require.Len(t, families[0].Metric, 1)
	point := families[0].Metric[0]
	assert.Equal(t, float64(1), point.Gauge.GetValue())
	require.Len(t, point.Label, 1)
	assert.Equal(t, "grafana_host_id", point.Label[0].GetName())
	assert.Equal(t, "configured-host", point.Label[0].GetValue())

	// And OTLP reports the same host identity using the dotted attribute name.
	require.Eventually(t, func() bool {
		select {
		case m := <-exporter.output:
			for _, scope := range m.ScopeMetrics {
				for _, metric := range scope.Metrics {
					if metric.Name != "traces.host.info" {
						continue
					}
					gauge := metric.Data.(metricdata.Gauge[int64])
					if len(gauge.DataPoints) != 1 {
						continue
					}
					p := gauge.DataPoints[0]
					assert.Equal(t, int64(1), p.Value)
					assert.Equal(t, 1, p.Attributes.Len())
					value, ok := p.Attributes.Value("grafana.host.id")
					assert.True(t, ok)
					assert.Equal(t, "configured-host", value.AsString())
					return true
				}
			}
		default:
		}
		return false
	}, time.Second, time.Millisecond)
	assert.Nil(t, span.Service.Metadata, "the terminal node does not decorate spans")

	// When the last active process terminates, Prometheus removes the series.
	events.Send(exec.ProcessEvent{Type: exec.ProcessEventTerminated, File: exec.New(exec.Init{Pid: 123})})
	require.Eventually(t, func() bool {
		f, err := registry.Gather()
		return err == nil && len(f) == 0
	}, time.Second, time.Millisecond)

	// Discard exports queued before termination, then verify OTLP also stops reporting the series.
	for len(exporter.output) > 0 {
		<-exporter.output
	}
	require.Eventually(t, func() bool {
		select {
		case m := <-exporter.output:
			for _, scope := range m.ScopeMetrics {
				for _, metric := range scope.Metrics {
					if gauge, ok := metric.Data.(metricdata.Gauge[int64]); ok && len(gauge.DataPoints) > 0 {
						return false
					}
				}
			}
			return true
		default:
			return false
		}
	}, time.Second, time.Millisecond)

	// Finally, both nodes stop without shutting down the shared exporter.
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("node did not stop")
	}
	assert.False(t, exporter.shutdown.Load(), "other nodes still own the shared exporter")
}

func TestHostActivityLifecycle(t *testing.T) {
	s := newState()
	now := time.Now()
	s.observe(1, now)
	s.observe(2, now)
	s.process(1, false)
	assert.True(t, s.hasActiveProcesses(now, time.Minute), "another process remains active")
	assert.False(t, s.hasActiveProcesses(now.Add(time.Minute), time.Minute), "TTL expires without activity")
	assert.True(t, s.hasActiveProcesses(now.Add(time.Minute), 2*time.Minute), "exporters can use different TTLs")
	s.process(2, false)
	s.observe(2, now)
	assert.False(t, s.hasActiveProcesses(now, time.Minute), "late spans cannot resurrect a terminated process")
	s.process(2, true)
	s.observe(2, now)
	assert.True(t, s.hasActiveProcesses(now, time.Minute), "PID reuse becomes active after creation")
}

func TestShouldReportHostInfo(t *testing.T) {
	span := request.Span{Type: request.EventTypeHTTP}
	assert.False(t, shouldReportHostInfo(&span))
	span.Service.Features = bexport.FeatureHostInfo
	assert.True(t, shouldReportHostInfo(&span))
	span.Service.ExportModes = services.NewExportModes()
	assert.False(t, shouldReportHostInfo(&span))
	span.Service.ExportModes = services.ExportModeUnset
	request.SetIgnoreMetrics(&span)
	assert.False(t, shouldReportHostInfo(&span))
}

func TestDisabled(t *testing.T) {
	_, err := OTELExport(OTELConfig{}, nil, nil)(t.Context())
	require.NoError(t, err)
	_, err = PromExport(PromConfig{}, nil, nil)(t.Context())
	require.NoError(t, err)
}

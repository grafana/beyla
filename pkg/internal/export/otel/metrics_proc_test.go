package otel

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/pkg/internal/export/attributes"
	"github.com/grafana/beyla/pkg/internal/infraolly/process"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/svc"
	"github.com/grafana/beyla/test/collector"
)

func TestProcMetrics_Aggregated(t *testing.T) {
	os.Setenv("OTEL_METRIC_EXPORT_INTERVAL", "100")
	defer restoreEnvAfterExecution()()
	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	otlp, err := collector.Start(ctx)
	require.NoError(t, err)

	// GIVEN an OTEL Metrics Exporter whose process CPU metrics do not consider the process.cpu.state
	includedAttributes := attributes.InclusionLists{
		Include: []string{"process_command"},
	}
	otelExporter, err := ProcMetricsExporterProvider(
		ctx, &global.ContextInfo{}, &ProcMetricsConfig{
			Metrics: &MetricsConfig{
				ReportersCacheLen: 100,
				CommonEndpoint:    otlp.ServerEndpoint,
				MetricsProtocol:   ProtocolHTTPProtobuf,
				Features:          []string{FeatureApplication, FeatureProcess},
				TTL:               3 * time.Minute,
			}, AttributeSelectors: attributes.Selection{
				attributes.ProcessCPUTime.Section:        includedAttributes,
				attributes.ProcessCPUUtilization.Section: includedAttributes,
				attributes.ProcessDiskIO.Section:         includedAttributes,
			},
		})()
	require.NoError(t, err)

	metrics := make(chan []*process.Status, 20)
	go otelExporter(metrics)

	// WHEN it receives process metrics
	metrics <- []*process.Status{
		{Command: "foo", Service: &svc.ID{UID: "foo"},
			CPUUtilisationWait: 3, CPUUtilisationSystem: 2, CPUUtilisationUser: 1,
			CPUTimeUserDelta: 30, CPUTimeWaitDelta: 20, CPUTimeSystemDelta: 10,
			IOReadBytes: 123, IOWriteBytes: 456,
		},
		{Command: "bar", Service: &svc.ID{UID: "bar"},
			CPUUtilisationWait: 31, CPUUtilisationSystem: 21, CPUUtilisationUser: 11,
			CPUTimeUserDelta: 301, CPUTimeWaitDelta: 201, CPUTimeSystemDelta: 101,
			IOReadBytes: 321, IOWriteBytes: 654,
		},
	}

	// THEN the metrics are exported adding system/user/wait times into a single datapoint
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records, timeout)
		require.Equal(t, "process.cpu.time", metric.Name)
		require.Equal(t, map[string]string{"process.command": "foo"}, metric.Attributes)
		require.EqualValues(t, 60, metric.FloatVal)
	})
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records, timeout)
		require.Equal(t, "process.cpu.time", metric.Name)
		require.Equal(t, map[string]string{"process.command": "bar"}, metric.Attributes)
		require.EqualValues(t, 603, metric.FloatVal)
	})
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records, timeout)
		require.Equal(t, "process.cpu.utilization", metric.Name)
		require.Equal(t, map[string]string{"process.command": "foo"}, metric.Attributes)
		require.EqualValues(t, 6, metric.FloatVal)
	})
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records, timeout)
		require.Equal(t, "process.cpu.utilization", metric.Name)
		require.Equal(t, map[string]string{"process.command": "bar"}, metric.Attributes)
		require.EqualValues(t, 63, metric.FloatVal)
	})
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records, timeout)
		require.Equal(t, "process.disk.io", metric.Name)
		require.Equal(t, map[string]string{"process.command": "foo"}, metric.Attributes)
		require.EqualValues(t, 123+456, metric.IntVal)
	})
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records, timeout)
		require.Equal(t, "process.disk.io", metric.Name)
		require.Equal(t, map[string]string{"process.command": "bar"}, metric.Attributes)
		require.EqualValues(t, 321+654, metric.IntVal)
	})

	// AND WHEN new metrics are received
	metrics <- []*process.Status{
		{Command: "foo", Service: &svc.ID{UID: "foo"},
			CPUUtilisationWait: 4, CPUUtilisationSystem: 1, CPUUtilisationUser: 2,
			CPUTimeUserDelta: 3, CPUTimeWaitDelta: 2, CPUTimeSystemDelta: 1,
		},
	}

	// THEN the counter is updated by adding values and the gauges change their values
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records, timeout)
		require.Equal(t, "process.cpu.time", metric.Name)
		require.Equal(t, map[string]string{"process.command": "foo"}, metric.Attributes)
		require.EqualValues(t, 66, metric.FloatVal)
	})
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records, timeout)
		require.Equal(t, "process.cpu.time", metric.Name)
		require.Equal(t, map[string]string{"process.command": "bar"}, metric.Attributes)
		require.EqualValues(t, 603, metric.FloatVal)
	})
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records, timeout)
		require.Equal(t, "process.cpu.utilization", metric.Name)
		require.Equal(t, map[string]string{"process.command": "foo"}, metric.Attributes)
		require.EqualValues(t, 7, metric.FloatVal)
	})
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records, timeout)
		require.Equal(t, "process.cpu.utilization", metric.Name)
		require.Equal(t, map[string]string{"process.command": "bar"}, metric.Attributes)
		require.EqualValues(t, 63, metric.FloatVal)
	})
}

func TestProcMetrics_Disaggregated(t *testing.T) {
	os.Setenv("OTEL_METRIC_EXPORT_INTERVAL", "100")
	defer restoreEnvAfterExecution()()
	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	otlp, err := collector.Start(ctx)
	require.NoError(t, err)

	// GIVEN an OTEL Metrics Exporter whose process CPU metrics consider the process.cpu.state
	includedAttributes := attributes.InclusionLists{
		Include: []string{"process_command", "process_cpu_state", "disk_io_direction"},
	}
	otelExporter, err := ProcMetricsExporterProvider(
		ctx, &global.ContextInfo{}, &ProcMetricsConfig{
			Metrics: &MetricsConfig{
				ReportersCacheLen: 100,
				CommonEndpoint:    otlp.ServerEndpoint,
				MetricsProtocol:   ProtocolHTTPProtobuf,
				Features:          []string{FeatureApplication, FeatureProcess},
				TTL:               3 * time.Minute,
			}, AttributeSelectors: attributes.Selection{
				attributes.ProcessCPUTime.Section:        includedAttributes,
				attributes.ProcessCPUUtilization.Section: includedAttributes,
				attributes.ProcessDiskIO.Section:         includedAttributes,
			},
		})()
	require.NoError(t, err)

	metrics := make(chan []*process.Status, 20)
	go otelExporter(metrics)

	// WHEN it receives process metrics
	metrics <- []*process.Status{
		{Command: "foo", Service: &svc.ID{UID: "foo"},
			CPUUtilisationWait: 3, CPUUtilisationSystem: 2, CPUUtilisationUser: 1,
			CPUTimeUserDelta: 30, CPUTimeWaitDelta: 20, CPUTimeSystemDelta: 10,
			IOReadBytes: 123, IOWriteBytes: 456,
		},
	}

	// THEN the metrics are exported aggregated by system/user/wait times
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records, timeout)
		require.Equal(t, "process.cpu.time", metric.Name)
		require.Equal(t, map[string]string{
			"process.command": "foo", "process.cpu.state": "user"}, metric.Attributes)
		require.EqualValues(t, 30, metric.FloatVal)
	})
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records, timeout)
		require.Equal(t, "process.cpu.time", metric.Name)
		require.Equal(t, map[string]string{
			"process.command": "foo", "process.cpu.state": "system"}, metric.Attributes)
		require.EqualValues(t, 10, metric.FloatVal)
	})
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records, timeout)
		require.Equal(t, "process.cpu.time", metric.Name)
		require.Equal(t, map[string]string{
			"process.command": "foo", "process.cpu.state": "wait"}, metric.Attributes)
		require.EqualValues(t, 20, metric.FloatVal)
	})
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records, timeout)
		require.Equal(t, "process.cpu.utilization", metric.Name)
		require.Equal(t, map[string]string{
			"process.command": "foo", "process.cpu.state": "user"}, metric.Attributes)
		require.EqualValues(t, 1, metric.FloatVal)
	})
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records, timeout)
		require.Equal(t, "process.cpu.utilization", metric.Name)
		require.Equal(t, map[string]string{
			"process.command": "foo", "process.cpu.state": "system"}, metric.Attributes)
		require.EqualValues(t, 2, metric.FloatVal)
	})
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records, timeout)
		require.Equal(t, "process.cpu.utilization", metric.Name)
		require.Equal(t, map[string]string{
			"process.command": "foo", "process.cpu.state": "wait"}, metric.Attributes)
		require.EqualValues(t, 3, metric.FloatVal)
	})
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records, timeout)
		require.Equal(t, "process.disk.io", metric.Name)
		require.Equal(t, map[string]string{"process.command": "foo", "disk.io.direction": "write"}, metric.Attributes)
		require.EqualValues(t, 456, metric.IntVal)
	})
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records, timeout)
		require.Equal(t, "process.disk.io", metric.Name)
		require.Equal(t, map[string]string{"process.command": "foo", "disk.io.direction": "read"}, metric.Attributes)
		require.EqualValues(t, 123, metric.IntVal)
	})
}

package otel

import (
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"

	"github.com/grafana/beyla/v2/pkg/export/extraattributes"
	"github.com/grafana/beyla/v2/pkg/internal/infraolly/process"
	"github.com/grafana/beyla/v2/pkg/test/collector"
)

const timeout = 3 * time.Second

func TestProcMetrics_Disaggregated(t *testing.T) {
	t.Setenv("OTEL_METRIC_EXPORT_INTERVAL", "100")
	ctx := t.Context()

	otlp, err := collector.Start(ctx)
	require.NoError(t, err)

	// GIVEN an OTEL Metrics Exporter whose process CPU metrics consider the cpu.mode
	includedAttributes := attributes.InclusionLists{
		Include: []string{"process_command", "cpu_mode", "disk_io_direction", "network_io_direction"},
	}
	mCfg := otelcfg.MetricsConfig{
		ReportersCacheLen: 100,
		CommonEndpoint:    otlp.ServerEndpoint,
		MetricsProtocol:   otelcfg.ProtocolHTTPProtobuf,
		Features:          []string{otelcfg.FeatureApplication, FeatureProcess},
		TTL:               3 * time.Minute,
		Instrumentations: []string{
			instrumentations.InstrumentationALL,
		},
	}
	instancer := &otelcfg.MetricsExporterInstancer{Cfg: &mCfg}

	procsInput := msg.NewQueue[[]*process.Status](msg.ChannelBufferLen(10))
	otelExporter, err := ProcMetricsExporterProvider(
		&global.ContextInfo{OTELMetricsExporter: instancer}, &ProcMetricsConfig{
			Metrics: &mCfg, SelectorCfg: &attributes.SelectorConfig{
				SelectionCfg: attributes.Selection{
					extraattributes.ProcessCPUTime.Section:        includedAttributes,
					extraattributes.ProcessCPUUtilization.Section: includedAttributes,
					extraattributes.ProcessDiskIO.Section:         includedAttributes,
					extraattributes.ProcessNetIO.Section:          includedAttributes,
				},
			},
		}, procsInput)(ctx)
	require.NoError(t, err)

	go otelExporter(ctx)

	// WHEN it receives process metrics
	procsInput.Send([]*process.Status{
		{ID: process.ID{Command: "foo", Service: &svc.Attrs{}, UID: svc.UID{Instance: "foo"}},
			CPUUtilisationWait: 3, CPUUtilisationSystem: 2, CPUUtilisationUser: 1,
			CPUTimeUserDelta: 30, CPUTimeWaitDelta: 20, CPUTimeSystemDelta: 10,
			IOReadBytesDelta: 123, IOWriteBytesDelta: 456,
			NetRcvBytesDelta: 10, NetTxBytesDelta: 20,
		},
	})

	// THEN the metrics are exported aggregated by system/user/wait times
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records(), timeout)
		require.Equal(t, "process.cpu.time", metric.Name)
		require.Equal(t, "foo", metric.ResourceAttributes["process.command"])
		require.Equal(t, map[string]string{"cpu.mode": "user"}, metric.Attributes)
		require.EqualValues(t, 30, metric.FloatVal)
	})
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records(), timeout)
		require.Equal(t, "process.cpu.time", metric.Name)
		require.Equal(t, "foo", metric.ResourceAttributes["process.command"])
		require.Equal(t, map[string]string{"cpu.mode": "system"}, metric.Attributes)
		require.EqualValues(t, 10, metric.FloatVal)
	})
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records(), timeout)
		require.Equal(t, "process.cpu.time", metric.Name)
		require.Equal(t, "foo", metric.ResourceAttributes["process.command"])
		require.Equal(t, map[string]string{"cpu.mode": "wait"}, metric.Attributes)
		require.EqualValues(t, 20, metric.FloatVal)
	})
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records(), timeout)
		require.Equal(t, "process.cpu.utilization", metric.Name)
		require.Equal(t, "foo", metric.ResourceAttributes["process.command"])
		require.Equal(t, map[string]string{"cpu.mode": "user"}, metric.Attributes)
		require.EqualValues(t, 1, metric.FloatVal)
	})
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records(), timeout)
		require.Equal(t, "process.cpu.utilization", metric.Name)
		require.Equal(t, "foo", metric.ResourceAttributes["process.command"])
		require.Equal(t, map[string]string{"cpu.mode": "system"}, metric.Attributes)
		require.EqualValues(t, 2, metric.FloatVal)
	})
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records(), timeout)
		require.Equal(t, "process.cpu.utilization", metric.Name)
		require.Equal(t, "foo", metric.ResourceAttributes["process.command"])
		require.Equal(t, map[string]string{"cpu.mode": "wait"}, metric.Attributes)
		require.EqualValues(t, 3, metric.FloatVal)
	})
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records(), timeout)
		require.Equal(t, "process.disk.io", metric.Name)
		require.Equal(t, "foo", metric.ResourceAttributes["process.command"])
		require.Equal(t, map[string]string{"disk.io.direction": "write"}, metric.Attributes)
		require.EqualValues(t, 456, metric.IntVal)
	})
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records(), timeout)
		require.Equal(t, "process.disk.io", metric.Name)
		require.Equal(t, "foo", metric.ResourceAttributes["process.command"])
		require.Equal(t, map[string]string{"disk.io.direction": "read"}, metric.Attributes)
		require.EqualValues(t, 123, metric.IntVal)
	})
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records(), timeout)
		require.Equal(t, "process.network.io", metric.Name)
		require.Equal(t, "foo", metric.ResourceAttributes["process.command"])
		require.Equal(t, map[string]string{"network.io.direction": "receive"}, metric.Attributes)
		require.EqualValues(t, 10, metric.IntVal)
	})
	test.Eventually(t, timeout, func(t require.TestingT) {
		metric := readChan(t, otlp.Records(), timeout)
		require.Equal(t, "process.network.io", metric.Name)
		require.Equal(t, "foo", metric.ResourceAttributes["process.command"])
		require.Equal(t, map[string]string{"network.io.direction": "transmit"}, metric.Attributes)
		require.EqualValues(t, 20, metric.IntVal)
	})
}

func TestGetFilteredProcessResourceAttrs(t *testing.T) {
	hostID := "test-host-id"

	service := &svc.Attrs{
		UID: svc.UID{
			Name:      "test-service",
			Instance:  "test-instance",
			Namespace: "test-namespace",
		},
		HostName:    "test-host",
		SDKLanguage: svc.InstrumentableGolang,
	}

	procID := &process.ID{
		ProcessID:       12345,
		ParentProcessID: 1000,
		Command:         "test-process",
		CommandLine:     "/bin/test-process --arg1 --arg2=value",
		CommandArgs:     []string{"/bin/test-process", "--arg1", "--arg2=value"},
		ExecName:        "test-process",
		ExecPath:        "/bin/test-process",
		User:            "testuser",
		Service:         service,
		UID:             service.UID,
	}

	attrSelector := attributes.Selection{
		extraattributes.ProcessCPUTime.Section: attributes.InclusionLists{
			Include: []string{"*"},
			Exclude: []string{"process.command_args", "process.exec_path"},
		},
	}

	result := getFilteredProcessResourceAttrs(hostID, procID, attrSelector)

	attrMap := make(map[string]string)
	for _, attr := range result {
		attrMap[string(attr.Key)] = attr.Value.AsString()
	}

	expectedBaseAttrs := []string{
		"service.name",
		"service.namespace",
		"telemetry.sdk.language",
		"telemetry.sdk.name",
		"telemetry.sdk.version",
		"host.name",
		"host.id",
	}

	for _, attrName := range expectedBaseAttrs {
		_, exists := attrMap[attrName]
		assert.True(t, exists, "Base attribute %s should always be included", attrName)
	}

	assert.Equal(t, "test-instance", attrMap["service.instance.id"])

	assert.Equal(t, "12345", attrMap["process.pid"])
	assert.Equal(t, "test-process", attrMap["process.command"])
	assert.Equal(t, "testuser", attrMap["process.owner"])

	_, hasCommandArgs := attrMap["process.command_args"]
	assert.False(t, hasCommandArgs, "process.command_args should be filtered out")

	_, hasExecPath := attrMap["process.exec_path"]
	assert.False(t, hasExecPath, "process.exec_path should be filtered out")

	attrSelector = attributes.Selection{
		extraattributes.ProcessMemoryUsage.Section: attributes.InclusionLists{
			Include: []string{"*"},
			Exclude: []string{"process.*"}, // Exclude all process attributes
		},
	}

	result = getFilteredProcessResourceAttrs(hostID, procID, attrSelector)

	attrMap = make(map[string]string)
	for _, attr := range result {
		attrMap[string(attr.Key)] = attr.Value.AsString()
	}

	for _, attrName := range expectedBaseAttrs {
		_, exists := attrMap[attrName]
		assert.True(t, exists, "Base attribute %s should always be included", attrName)
	}

	// process.pid should be in the list because it's now part of the
	// resource attributes
	processAttrs := []string{
		"process.parent_pid",
		"process.command",
		"process.command_line",
		"process.command_args",
		"process.exec_name",
		"process.exec_path",
		"process.owner",
	}

	for _, attrName := range processAttrs {
		_, exists := attrMap[attrName]
		assert.False(t, exists, "Process attribute %s should be filtered out", attrName)
	}
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

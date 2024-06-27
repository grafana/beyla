package prom

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/pkg/internal/connector"
	"github.com/grafana/beyla/pkg/internal/export/attributes"
	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/infraolly/process"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/svc"
)

func TestProcPrometheusEndpoint_AggregatedMetrics(t *testing.T) {
	now := syncedClock{now: time.Now()}
	timeNow = now.Now

	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()
	openPort, err := test.FreeTCPPort()
	require.NoError(t, err)
	promURL := fmt.Sprintf("http://127.0.0.1:%d/metrics", openPort)

	// GIVEN a Prometheus Metrics Exporter whose process CPU metrics do not consider the process_cpu_state
	attribs := attributes.InclusionLists{
		Include: []string{"process_command"},
	}
	exporter, err := ProcPrometheusEndpoint(
		ctx, &global.ContextInfo{Prometheus: &connector.PrometheusManager{}},
		&ProcPrometheusConfig{Metrics: &PrometheusConfig{
			Port:                        openPort,
			Path:                        "/metrics",
			TTL:                         3 * time.Minute,
			SpanMetricsServiceCacheSize: 10,
			Features:                    []string{otel.FeatureApplication, otel.FeatureProcess},
		}, AttributeSelectors: attributes.Selection{
			attributes.ProcessCPUTime.Section:        attribs,
			attributes.ProcessCPUUtilization.Section: attribs,
			attributes.ProcessDiskIO.Section:         attribs,
			attributes.ProcessNetIO.Section:          attribs,
		}},
	)()
	require.NoError(t, err)

	metrics := make(chan []*process.Status, 20)
	go exporter(metrics)

	// WHEN it receives process metrics
	metrics <- []*process.Status{
		{Service: &svc.ID{}, Command: "foo",
			CPUUtilisationWait: 3, CPUUtilisationSystem: 2, CPUUtilisationUser: 1,
			CPUTimeUserDelta: 30, CPUTimeWaitDelta: 20, CPUTimeSystemDelta: 10,
			IOReadBytesDelta: 123, IOWriteBytesDelta: 456,
			NetRcvBytesDelta: 12, NetTxBytesDelta: 34,
		},
		{Service: &svc.ID{}, Command: "bar",
			CPUUtilisationWait: 31, CPUUtilisationSystem: 21, CPUUtilisationUser: 11,
			CPUTimeUserDelta: 301, CPUTimeWaitDelta: 201, CPUTimeSystemDelta: 101,
			IOReadBytesDelta: 321, IOWriteBytesDelta: 654,
			NetRcvBytesDelta: 1, NetTxBytesDelta: 3,
		},
	}

	// THEN the metrics are exported adding system/user/wait times into a single datapoint
	test.Eventually(t, timeout, func(t require.TestingT) {
		exported := getMetrics(t, promURL)
		assert.Contains(t, exported, `process_cpu_utilization_ratio{process_command="foo"} 6`)
		assert.Contains(t, exported, `process_cpu_time_seconds_total{process_command="foo"} 60`)
		assert.Contains(t, exported, `process_cpu_utilization_ratio{process_command="bar"} 63`)
		assert.Contains(t, exported, `process_cpu_time_seconds_total{process_command="bar"} 603`)
		assert.Contains(t, exported, `process_disk_io_bytes_total{process_command="foo"} 579`)
		assert.Contains(t, exported, `process_disk_io_bytes_total{process_command="bar"} 975`)
		assert.Contains(t, exported, `process_network_io_bytes_total{process_command="foo"} 46`)
		assert.Contains(t, exported, `process_network_io_bytes_total{process_command="bar"} 4`)
	})

	// AND WHEN new metrics are received
	metrics <- []*process.Status{
		{Service: &svc.ID{}, Command: "foo",
			CPUUtilisationWait: 4, CPUUtilisationSystem: 1, CPUUtilisationUser: 2,
			CPUTimeUserDelta: 3, CPUTimeWaitDelta: 2, CPUTimeSystemDelta: 1,
			IOReadBytesDelta: 31, IOWriteBytesDelta: 10,
			NetRcvBytesDelta: 1, NetTxBytesDelta: 3,
		},
	}

	// THEN the counter is updated by adding values and the gauges change their values
	test.Eventually(t, timeout, func(t require.TestingT) {
		exported := getMetrics(t, promURL)
		assert.Contains(t, exported, `process_cpu_utilization_ratio{process_command="foo"} 7`)
		assert.Contains(t, exported, `process_cpu_time_seconds_total{process_command="foo"} 66`)
		assert.Contains(t, exported, `process_cpu_utilization_ratio{process_command="bar"} 63`)
		assert.Contains(t, exported, `process_cpu_time_seconds_total{process_command="bar"} 603`)
		assert.Contains(t, exported, `process_disk_io_bytes_total{process_command="foo"} 620`)
		assert.Contains(t, exported, `process_disk_io_bytes_total{process_command="bar"} 975`)
		assert.Contains(t, exported, `process_network_io_bytes_total{process_command="foo"} 50`)
		assert.Contains(t, exported, `process_network_io_bytes_total{process_command="bar"} 4`)
	})
}

func TestProcPrometheusEndpoint_DisaggregatedMetrics(t *testing.T) {
	now := syncedClock{now: time.Now()}
	timeNow = now.Now

	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()
	openPort, err := test.FreeTCPPort()
	require.NoError(t, err)
	promURL := fmt.Sprintf("http://127.0.0.1:%d/metrics", openPort)

	// GIVEN a Prometheus Metrics Exporter whose process CPU metrics consider the process_cpu_state
	attribs := attributes.InclusionLists{
		Include: []string{"process_command", "process_cpu_state", "disk_io_direction", "network_io_direction"},
	}
	exporter, err := ProcPrometheusEndpoint(
		ctx, &global.ContextInfo{Prometheus: &connector.PrometheusManager{}},
		&ProcPrometheusConfig{Metrics: &PrometheusConfig{
			Port:                        openPort,
			Path:                        "/metrics",
			TTL:                         3 * time.Minute,
			SpanMetricsServiceCacheSize: 10,
			Features:                    []string{otel.FeatureApplication, otel.FeatureProcess},
		}, AttributeSelectors: attributes.Selection{
			attributes.ProcessCPUTime.Section:        attribs,
			attributes.ProcessCPUUtilization.Section: attribs,
			attributes.ProcessDiskIO.Section:         attribs,
			attributes.ProcessNetIO.Section:          attribs,
		}},
	)()
	require.NoError(t, err)

	metrics := make(chan []*process.Status, 20)
	go exporter(metrics)

	// WHEN it receives process metrics
	metrics <- []*process.Status{
		{Service: &svc.ID{}, Command: "foo",
			CPUUtilisationWait: 3, CPUUtilisationSystem: 2, CPUUtilisationUser: 1,
			CPUTimeUserDelta: 30, CPUTimeWaitDelta: 20, CPUTimeSystemDelta: 10,
			IOReadBytesDelta: 123, IOWriteBytesDelta: 456,
			NetRcvBytesDelta: 1, NetTxBytesDelta: 3,
		},
	}

	// THEN the metrics are exported aggregated by system/user/wait times
	test.Eventually(t, timeout, func(t require.TestingT) {
		exported := getMetrics(t, promURL)
		assert.Contains(t, exported, `process_cpu_utilization_ratio{process_command="foo",process_cpu_state="user"} 1`)
		assert.Contains(t, exported, `process_cpu_utilization_ratio{process_command="foo",process_cpu_state="system"} 2`)
		assert.Contains(t, exported, `process_cpu_utilization_ratio{process_command="foo",process_cpu_state="wait"} 3`)
		assert.Contains(t, exported, `process_cpu_time_seconds_total{process_command="foo",process_cpu_state="user"} 30`)
		assert.Contains(t, exported, `process_cpu_time_seconds_total{process_command="foo",process_cpu_state="system"} 10`)
		assert.Contains(t, exported, `process_cpu_time_seconds_total{process_command="foo",process_cpu_state="wait"} 20`)
		assert.Contains(t, exported, `process_disk_io_bytes_total{disk_io_direction="read",process_command="foo"} 123`)
		assert.Contains(t, exported, `process_disk_io_bytes_total{disk_io_direction="write",process_command="foo"} 456`)
		assert.Contains(t, exported, `process_network_io_bytes_total{network_io_direction="transmit",process_command="foo"} 3`)
		assert.Contains(t, exported, `process_network_io_bytes_total{network_io_direction="receive",process_command="foo"} 1`)
	})

	// AND WHEN new metrics are received
	metrics <- []*process.Status{
		{Service: &svc.ID{}, Command: "foo",
			CPUUtilisationWait: 4, CPUUtilisationSystem: 1, CPUUtilisationUser: 2,
			CPUTimeUserDelta: 3, CPUTimeWaitDelta: 2, CPUTimeSystemDelta: 1,
			IOReadBytesDelta: 3, IOWriteBytesDelta: 2,
			NetRcvBytesDelta: 10, NetTxBytesDelta: 30,
		},
	}

	// THEN the counter is updated by adding values and the gauges change their values
	test.Eventually(t, timeout, func(t require.TestingT) {
		exported := getMetrics(t, promURL)
		assert.Contains(t, exported, `process_cpu_utilization_ratio{process_command="foo",process_cpu_state="user"} 2`)
		assert.Contains(t, exported, `process_cpu_utilization_ratio{process_command="foo",process_cpu_state="system"} 1`)
		assert.Contains(t, exported, `process_cpu_utilization_ratio{process_command="foo",process_cpu_state="wait"} 4`)
		assert.Contains(t, exported, `process_cpu_time_seconds_total{process_command="foo",process_cpu_state="user"} 33`)
		assert.Contains(t, exported, `process_cpu_time_seconds_total{process_command="foo",process_cpu_state="system"} 11`)
		assert.Contains(t, exported, `process_cpu_time_seconds_total{process_command="foo",process_cpu_state="wait"} 22`)
		assert.Contains(t, exported, `process_disk_io_bytes_total{disk_io_direction="read",process_command="foo"} 126`)
		assert.Contains(t, exported, `process_disk_io_bytes_total{disk_io_direction="write",process_command="foo"} 458`)
		assert.Contains(t, exported, `process_network_io_bytes_total{network_io_direction="transmit",process_command="foo"} 33`)
		assert.Contains(t, exported, `process_network_io_bytes_total{network_io_direction="receive",process_command="foo"} 11`)
	})
}

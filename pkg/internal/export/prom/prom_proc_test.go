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
	exporter, err := ProcPrometheusEndpoint(
		ctx, &global.ContextInfo{Prometheus: &connector.PrometheusManager{}},
		&ProcPrometheusConfig{Metrics: &PrometheusConfig{
			Port:                        openPort,
			Path:                        "/metrics",
			TTL:                         3 * time.Minute,
			SpanMetricsServiceCacheSize: 10,
			Features:                    []string{otel.FeatureApplication, otel.FeatureProcess},
		}, AttributeSelectors: attributes.Selection{
			attributes.ProcessCPUTime.Section: attributes.InclusionLists{
				Include: []string{"process_command"},
			},
			attributes.ProcessCPUUtilization.Section: attributes.InclusionLists{
				Include: []string{"process_command"},
			},
		}},
	)()
	require.NoError(t, err)

	metrics := make(chan []*process.Status, 20)
	go exporter(metrics)

	// WHEN it receives process metrics
	metrics <- []*process.Status{
		{Command: "foo",
			CPUUtilisationWait: 3, CPUUtilisationSystem: 2, CPUUtilisationUser: 1,
			CPUTimeUserDelta: 30, CPUTimeWaitDelta: 20, CPUTimeSystemDelta: 10,
		},
		{Command: "bar",
			CPUUtilisationWait: 31, CPUUtilisationSystem: 21, CPUUtilisationUser: 11,
			CPUTimeUserDelta: 301, CPUTimeWaitDelta: 201, CPUTimeSystemDelta: 101,
		},
	}

	// THEN the metrics are exported aggregated by system/user/wait times
	test.Eventually(t, timeout, func(t require.TestingT) {
		exported := getMetrics(t, promURL)
		assert.Contains(t, exported, `process_cpu_utilization_ratio{process_command="foo"} 6`)
		assert.Contains(t, exported, `process_cpu_time_seconds_total{process_command="foo"} 60`)
		assert.Contains(t, exported, `process_cpu_utilization_ratio{process_command="bar"} 63`)
		assert.Contains(t, exported, `process_cpu_time_seconds_total{process_command="bar"} 603`)
	})

	// AND WHEN new metrics are received
	metrics <- []*process.Status{
		{Command: "foo",
			CPUUtilisationWait: 4, CPUUtilisationSystem: 1, CPUUtilisationUser: 2,
			CPUTimeUserDelta: 3, CPUTimeWaitDelta: 2, CPUTimeSystemDelta: 1,
		},
	}

	// THEN the counter is updated by adding values and the gauges change their values
	test.Eventually(t, timeout, func(t require.TestingT) {
		exported := getMetrics(t, promURL)
		assert.Contains(t, exported, `process_cpu_utilization_ratio{process_command="foo"} 7`)
		assert.Contains(t, exported, `process_cpu_time_seconds_total{process_command="foo"} 66`)
		assert.Contains(t, exported, `process_cpu_utilization_ratio{process_command="bar"} 63`)
		assert.Contains(t, exported, `process_cpu_time_seconds_total{process_command="bar"} 603`)
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

	// GIVEN a Prometheus Metrics Exporter whose process CPU consider the process_cpu_state
	exporter, err := ProcPrometheusEndpoint(
		ctx, &global.ContextInfo{Prometheus: &connector.PrometheusManager{}},
		&ProcPrometheusConfig{Metrics: &PrometheusConfig{
			Port:                        openPort,
			Path:                        "/metrics",
			TTL:                         3 * time.Minute,
			SpanMetricsServiceCacheSize: 10,
			Features:                    []string{otel.FeatureApplication, otel.FeatureProcess},
		}, AttributeSelectors: attributes.Selection{
			attributes.ProcessCPUTime.Section: attributes.InclusionLists{
				Include: []string{"process_cpu_state", "process_command"},
			},
			attributes.ProcessCPUUtilization.Section: attributes.InclusionLists{
				Include: []string{"process_cpu_state", "process_command"},
			},
		}},
	)()
	require.NoError(t, err)

	metrics := make(chan []*process.Status, 20)
	go exporter(metrics)

	// WHEN it receives process metrics
	metrics <- []*process.Status{
		{Command: "foo",
			CPUUtilisationWait: 3, CPUUtilisationSystem: 2, CPUUtilisationUser: 1,
			CPUTimeUserDelta: 30, CPUTimeWaitDelta: 20, CPUTimeSystemDelta: 10,
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
	})

	// AND WHEN new metrics are received
	metrics <- []*process.Status{
		{Command: "foo",
			CPUUtilisationWait: 4, CPUUtilisationSystem: 1, CPUUtilisationUser: 2,
			CPUTimeUserDelta: 3, CPUTimeWaitDelta: 2, CPUTimeSystemDelta: 1,
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
	})
}

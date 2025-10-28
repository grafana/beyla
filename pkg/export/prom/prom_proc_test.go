package prom

import (
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/connector"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"

	"github.com/grafana/beyla/v2/pkg/export/extraattributes"
	"github.com/grafana/beyla/v2/pkg/export/otel"
	"github.com/grafana/beyla/v2/pkg/internal/infraolly/process"
)

const timeout = 3 * time.Second

func TestProcPrometheusEndpoint_AggregatedMetrics(t *testing.T) {
	now := syncedClock{now: time.Now()}
	timeNow = now.Now

	ctx := t.Context()
	openPort, err := test.FreeTCPPort()
	require.NoError(t, err)
	promURL := fmt.Sprintf("http://127.0.0.1:%d/metrics", openPort)

	// GIVEN a Prometheus Metrics Exporter whose process CPU metrics do not consider the cpu_mode
	attribs := attributes.InclusionLists{
		Include: []string{"process_command"},
	}
	procsInput := msg.NewQueue[[]*process.Status](msg.ChannelBufferLen(10))
	exporter, err := ProcPrometheusEndpoint(
		&global.ContextInfo{Prometheus: &connector.PrometheusManager{}},
		&ProcPrometheusConfig{Metrics: &prom.PrometheusConfig{
			Port:                        openPort,
			Path:                        "/metrics",
			TTL:                         3 * time.Minute,
			SpanMetricsServiceCacheSize: 10,
			Features:                    []string{otelcfg.FeatureApplication, otel.FeatureProcess},
		}, SelectorCfg: &attributes.SelectorConfig{
			SelectionCfg: attributes.Selection{
				extraattributes.ProcessCPUTime.Section:        attribs,
				extraattributes.ProcessCPUUtilization.Section: attribs,
				extraattributes.ProcessDiskIO.Section:         attribs,
				extraattributes.ProcessNetIO.Section:          attribs,
			},
		}},
		procsInput,
	)(ctx)
	require.NoError(t, err)

	go exporter(ctx)

	// WHEN it receives process metrics
	procsInput.Send([]*process.Status{
		{ID: process.ID{Service: &svc.Attrs{}, Command: "foo"},
			CPUUtilisationWait: 3, CPUUtilisationSystem: 2, CPUUtilisationUser: 1,
			CPUTimeUserDelta: 30, CPUTimeWaitDelta: 20, CPUTimeSystemDelta: 10,
			IOReadBytesDelta: 123, IOWriteBytesDelta: 456,
			NetRcvBytesDelta: 12, NetTxBytesDelta: 34,
		},
		{ID: process.ID{Service: &svc.Attrs{}, Command: "bar"},
			CPUUtilisationWait: 31, CPUUtilisationSystem: 21, CPUUtilisationUser: 11,
			CPUTimeUserDelta: 301, CPUTimeWaitDelta: 201, CPUTimeSystemDelta: 101,
			IOReadBytesDelta: 321, IOWriteBytesDelta: 654,
			NetRcvBytesDelta: 1, NetTxBytesDelta: 3,
		},
	})

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
	procsInput.Send([]*process.Status{
		{ID: process.ID{Service: &svc.Attrs{}, Command: "foo"},
			CPUUtilisationWait: 4, CPUUtilisationSystem: 1, CPUUtilisationUser: 2,
			CPUTimeUserDelta: 3, CPUTimeWaitDelta: 2, CPUTimeSystemDelta: 1,
			IOReadBytesDelta: 31, IOWriteBytesDelta: 10,
			NetRcvBytesDelta: 1, NetTxBytesDelta: 3,
		},
	})

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

	ctx := t.Context()
	openPort, err := test.FreeTCPPort()
	require.NoError(t, err)
	promURL := fmt.Sprintf("http://127.0.0.1:%d/metrics", openPort)

	// GIVEN a Prometheus Metrics Exporter whose process CPU metrics consider the cpu_mode
	attribs := attributes.InclusionLists{
		Include: []string{"process_command", "cpu_mode", "disk_io_direction", "network_io_direction"},
	}
	procsInput := msg.NewQueue[[]*process.Status](msg.ChannelBufferLen(10))
	exporter, err := ProcPrometheusEndpoint(
		&global.ContextInfo{Prometheus: &connector.PrometheusManager{}},
		&ProcPrometheusConfig{Metrics: &prom.PrometheusConfig{
			Port:                        openPort,
			Path:                        "/metrics",
			TTL:                         3 * time.Minute,
			SpanMetricsServiceCacheSize: 10,
			Features:                    []string{otelcfg.FeatureApplication, otel.FeatureProcess},
		}, SelectorCfg: &attributes.SelectorConfig{
			SelectionCfg: attributes.Selection{
				extraattributes.ProcessCPUTime.Section:        attribs,
				extraattributes.ProcessCPUUtilization.Section: attribs,
				extraattributes.ProcessDiskIO.Section:         attribs,
				extraattributes.ProcessNetIO.Section:          attribs,
			},
		}},
		procsInput,
	)(ctx)
	require.NoError(t, err)

	go exporter(ctx)

	// WHEN it receives process metrics
	procsInput.Send([]*process.Status{
		{ID: process.ID{Service: &svc.Attrs{}, Command: "foo"},
			CPUUtilisationWait: 3, CPUUtilisationSystem: 2, CPUUtilisationUser: 1,
			CPUTimeUserDelta: 30, CPUTimeWaitDelta: 20, CPUTimeSystemDelta: 10,
			IOReadBytesDelta: 123, IOWriteBytesDelta: 456,
			NetRcvBytesDelta: 1, NetTxBytesDelta: 3,
		},
	})

	// THEN the metrics are exported aggregated by system/user/wait times
	test.Eventually(t, timeout, func(t require.TestingT) {
		exported := getMetrics(t, promURL)
		assert.Contains(t, exported, `process_cpu_utilization_ratio{cpu_mode="user",process_command="foo"} 1`)
		assert.Contains(t, exported, `process_cpu_utilization_ratio{cpu_mode="system",process_command="foo"} 2`)
		assert.Contains(t, exported, `process_cpu_utilization_ratio{cpu_mode="wait",process_command="foo"} 3`)
		assert.Contains(t, exported, `process_cpu_time_seconds_total{cpu_mode="user",process_command="foo"} 30`)
		assert.Contains(t, exported, `process_cpu_time_seconds_total{cpu_mode="system",process_command="foo"} 10`)
		assert.Contains(t, exported, `process_cpu_time_seconds_total{cpu_mode="wait",process_command="foo"} 20`)
		assert.Contains(t, exported, `process_disk_io_bytes_total{disk_io_direction="read",process_command="foo"} 123`)
		assert.Contains(t, exported, `process_disk_io_bytes_total{disk_io_direction="write",process_command="foo"} 456`)
		assert.Contains(t, exported, `process_network_io_bytes_total{network_io_direction="transmit",process_command="foo"} 3`)
		assert.Contains(t, exported, `process_network_io_bytes_total{network_io_direction="receive",process_command="foo"} 1`)
	})

	// AND WHEN new metrics are received
	procsInput.Send([]*process.Status{
		{ID: process.ID{Service: &svc.Attrs{}, Command: "foo"},
			CPUUtilisationWait: 4, CPUUtilisationSystem: 1, CPUUtilisationUser: 2,
			CPUTimeUserDelta: 3, CPUTimeWaitDelta: 2, CPUTimeSystemDelta: 1,
			IOReadBytesDelta: 3, IOWriteBytesDelta: 2,
			NetRcvBytesDelta: 10, NetTxBytesDelta: 30,
		},
	})

	// THEN the counter is updated by adding values and the gauges change their values
	test.Eventually(t, timeout, func(t require.TestingT) {
		exported := getMetrics(t, promURL)
		assert.Contains(t, exported, `process_cpu_utilization_ratio{cpu_mode="user",process_command="foo"} 2`)
		assert.Contains(t, exported, `process_cpu_utilization_ratio{cpu_mode="system",process_command="foo"} 1`)
		assert.Contains(t, exported, `process_cpu_utilization_ratio{cpu_mode="wait",process_command="foo"} 4`)
		assert.Contains(t, exported, `process_cpu_time_seconds_total{cpu_mode="user",process_command="foo"} 33`)
		assert.Contains(t, exported, `process_cpu_time_seconds_total{cpu_mode="system",process_command="foo"} 11`)
		assert.Contains(t, exported, `process_cpu_time_seconds_total{cpu_mode="wait",process_command="foo"} 22`)
		assert.Contains(t, exported, `process_disk_io_bytes_total{disk_io_direction="read",process_command="foo"} 126`)
		assert.Contains(t, exported, `process_disk_io_bytes_total{disk_io_direction="write",process_command="foo"} 458`)
		assert.Contains(t, exported, `process_network_io_bytes_total{network_io_direction="transmit",process_command="foo"} 33`)
		assert.Contains(t, exported, `process_network_io_bytes_total{network_io_direction="receive",process_command="foo"} 11`)
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

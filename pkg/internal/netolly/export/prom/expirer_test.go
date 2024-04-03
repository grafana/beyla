package prom

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/pkg/internal/connector"
	"github.com/grafana/beyla/pkg/internal/export/prom"
	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
)

func TestMetricsExpiration(t *testing.T) {
	slog.SetLogLoggerLevel(slog.LevelDebug)
	now := time.Now()
	timeNow = func() time.Time {
		return now
	}

	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()
	openPort, err := test.FreeTCPPort()
	require.NoError(t, err)
	promURL := fmt.Sprintf("http://127.0.0.1:%d/metrics", openPort)
	require.NoError(t, err)

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

	metrics <- []*ebpf.Record{
		{Attrs: ebpf.RecordAttrs{SrcName: "foo", DstName: "bar"},
			NetFlowRecordT: ebpf.NetFlowRecordT{Metrics: ebpf.NetFlowMetrics{Bytes: 123}}},
		{Attrs: ebpf.RecordAttrs{SrcName: "baz", DstName: "bae"},
			NetFlowRecordT: ebpf.NetFlowRecordT{Metrics: ebpf.NetFlowMetrics{Bytes: 456}}},
	}

	time.Sleep(2 * time.Second)

	AQUI PARSEAR SIMPLEMENTE QUE EL RESPONSE CONTAINS
	beyla_network_flow_bytes_total{dst_name="bae",src_name="baz"} 123
	beyla_network_flow_bytes_total{dst_name="bar",src_name="foo"} 456
	reported := getMetrics(t, promURL)
	fmt.Println("reported", reported)

}

func getMetrics(t *testing.T, promURL string) string {
	resp, err := http.Get(promURL)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(body)
}

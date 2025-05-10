package appolly

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/export/otel"
	"github.com/grafana/beyla/v2/pkg/export/prom"
	"github.com/grafana/beyla/v2/pkg/internal/connector"
	"github.com/grafana/beyla/v2/pkg/internal/discover"
	"github.com/grafana/beyla/v2/pkg/internal/ebpf"
	"github.com/grafana/beyla/v2/pkg/internal/exec"
	"github.com/grafana/beyla/v2/pkg/internal/pipe/global"
)

func TestProcessEventsHandled(t *testing.T) {
	instr, err := New(
		context.Background(),
		&global.ContextInfo{
			Prometheus: &connector.PrometheusManager{},
		},
		&beyla.Config{
			Prometheus: prom.PrometheusConfig{
				Path:     "/metrics",
				Port:     8080,
				Features: []string{otel.FeatureApplication},
				TTL:      time.Hour,
			},
		},
	)

	assert.NoError(t, err)
	assert.True(t, instr.processEventsEnabled())

	instr, err = New(
		context.Background(),
		&global.ContextInfo{
			Prometheus: &connector.PrometheusManager{},
		},
		&beyla.Config{
			Metrics: otel.MetricsConfig{
				MetricsEndpoint:   "http://something",
				ReportersCacheLen: 10,
				Features:          []string{otel.FeatureApplication},
			},
		},
	)

	assert.NoError(t, err)
	assert.True(t, instr.processEventsEnabled())

	instr, err = New(
		context.Background(),
		&global.ContextInfo{
			Prometheus: &connector.PrometheusManager{},
		},
		&beyla.Config{
			Traces: otel.TracesConfig{
				TracesEndpoint: "http://something",
			},
		},
	)

	assert.NoError(t, err)
	assert.False(t, instr.processEventsEnabled())
}

func TestProcessEventsLoopDoesntBlock(t *testing.T) {
	instr, err := New(
		context.Background(),
		&global.ContextInfo{
			Prometheus: &connector.PrometheusManager{},
		},
		&beyla.Config{
			ChannelBufferLen: 1,
			Traces: otel.TracesConfig{
				TracesEndpoint: "http://something",
			},
		},
	)

	events := make(chan discover.Event[*ebpf.Instrumentable])

	go instr.instrumentedEventLoop(context.Background(), events)

	for i := 0; i < 100; i++ {
		events <- discover.Event[*ebpf.Instrumentable]{
			Obj:  &ebpf.Instrumentable{FileInfo: &exec.FileInfo{Pid: int32(i)}},
			Type: discover.EventCreated,
		}
	}

	assert.NoError(t, err)
}

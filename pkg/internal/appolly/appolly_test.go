package appolly

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/ebpf"
	"go.opentelemetry.io/obi/pkg/export/connector"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"

	"github.com/grafana/beyla/v2/pkg/beyla"
)

func TestProcessEventsLoopDoesntBlock(t *testing.T) {
	instr, err := New(
		context.Background(),
		&global.ContextInfo{
			Prometheus:             &connector.PrometheusManager{},
			OverrideAppExportQueue: msg.NewQueue[[]request.Span](msg.Name("test"), msg.ChannelBufferLen(1)),
		},
		&beyla.Config{
			ChannelBufferLen: 1,
			Traces: otelcfg.TracesConfig{
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

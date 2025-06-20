package appolly

import (
	"context"
	"testing"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/connector"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/discover"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/exec"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/pipe/global"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/otel"
	"github.com/stretchr/testify/assert"

	"github.com/grafana/beyla/v2/pkg/beyla"
)

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

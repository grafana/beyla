package appolly

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	appruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/ebpf"
	"go.opentelemetry.io/obi/pkg/export/connector"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"

	"github.com/grafana/beyla/v3/pkg/beyla"
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
			Obj:  &ebpf.Instrumentable{FileInfo: exec.New(exec.Init{Pid: app.PID(i)})},
			Type: discover.EventCreated,
		}
	}

	assert.NoError(t, err)
}

func TestHandleProcessEventDrainsOnlyTerminatingWorkerFinal(t *testing.T) {
	processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(2))
	events := processEvents.Subscribe()
	instrumenter := &Instrumenter{processEventInput: processEvents}
	parent := exec.New(exec.Init{Pid: 100})
	first := exec.New(exec.Init{Pid: 101})
	first.SetRuntimeMetricServiceSource(parent)
	second := exec.New(exec.Init{Pid: 102})
	second.SetRuntimeMetricServiceSource(parent)
	parent.SetPythonRuntimeMetricFinal(appruntime.PythonRuntimeMetricFinal{PID: 101, Generation: 1})
	parent.SetPythonRuntimeMetricFinal(appruntime.PythonRuntimeMetricFinal{PID: 102, Generation: 2})

	instrumenter.handleAndDispatchProcessEvent(exec.ProcessEvent{
		Type: exec.ProcessEventTerminated,
		File: first,
	})

	event := <-events
	require.Len(t, event.FinalPythonRuntimeMetrics, 1)
	assert.Equal(t, app.PID(101), event.FinalPythonRuntimeMetrics[0].PID)
	remaining, ok := parent.TakePythonRuntimeMetricFinal(102)
	require.True(t, ok)
	assert.Equal(t, uint64(2), remaining.Generation)
}

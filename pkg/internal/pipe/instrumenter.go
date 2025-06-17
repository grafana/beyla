package pipe

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/app/request"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/exec"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/pipe"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/pipe/global"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/instrumenter"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/swarm"

	"github.com/grafana/beyla/v2/pkg/beyla"
)

func ilog() *slog.Logger {
	return slog.With("component", "BeylaInstrumenter")
}

// Build instantiates the whole instrumentation --> processing --> submit
// pipeline graph and returns it as a startable item
func Build(ctx context.Context, config *beyla.Config, ctxInfo *global.ContextInfo, tracesCh *msg.Queue[[]request.Span], processEventsCh *msg.Queue[exec.ProcessEvent]) (*swarm.Runner, error) {

	exportableSpans := ctxInfo.OverrideAppExportQueue
	if exportableSpans == nil {
		exportableSpans = msg.NewQueue[[]request.Span](msg.ChannelBufferLen(config.ChannelBufferLen))
		instrumenter.OverrideAppExportQueue(exportableSpans)
	}
	// a swarm containing two swarms
	// 1. OBI's actual pipe.Build swarm
	// 2. the process metrics swarm pipeline, connected to the output of (1)
	swi := &swarm.Instancer{}
	swi.Add(func(ctx context.Context) (swarm.RunFunc, error) {
		obiSwarm, err := pipe.Build(ctx, config.AsOBI(), ctxInfo, tracesCh, processEventsCh)
		if err != nil {
			return nil, fmt.Errorf("instantiating OBI app pipeline: %w", err)
		}
		return func(ctx context.Context) {
			select {
			case <-ctx.Done():
				ilog().Debug("context done, stopping OBI internal swarm")
			case <-obiSwarm.Start(ctx):
				ilog().Debug("OBI internal swarm stopped")
			}
		}, nil
	})

	// process subpipeline optionally starts another pipeline only to collect and export data
	// about the processes of an instrumented application
	swi.Add(ProcessMetricsSwarmInstancer(ctxInfo, config, exportableSpans))

	return swi.Instance(ctx)
}

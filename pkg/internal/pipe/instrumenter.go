package pipe

import (
	"context"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/obi/pkg/app/request"
	"go.opentelemetry.io/obi/pkg/components/exec"
	"go.opentelemetry.io/obi/pkg/components/pipe"
	"go.opentelemetry.io/obi/pkg/components/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"

	"github.com/grafana/beyla/v2/pkg/beyla"
)

func ilog() *slog.Logger {
	return slog.With("component", "BeylaInstrumenter")
}

// Build instantiates the whole instrumentation --> processing --> submit
// pipeline graph and returns it as a startable item
func Build(ctx context.Context, config *beyla.Config, ctxInfo *global.ContextInfo, tracesCh *msg.Queue[[]request.Span], processEventsCh *msg.Queue[exec.ProcessEvent]) (*swarm.Runner, error) {

	if ctxInfo.OverrideAppExportQueue == nil {
		ctxInfo.OverrideAppExportQueue = msg.NewQueue[[]request.Span](
			msg.ChannelBufferLen(config.ChannelBufferLen),
		)
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
			obiFinished := obiSwarm.Start(ctx)
			select {
			case <-ctx.Done():
				ilog().Debug("context done, stopping OBI internal swarm")
			case <-obiFinished:
				ilog().Debug("OBI internal swarm stopped")
			}
		}, nil
	})

	// process subpipeline optionally starts another pipeline only to collect and export data
	// about the processes of an instrumented application
	swi.Add(ProcessMetricsSwarmInstancer(ctxInfo, config, ctxInfo.OverrideAppExportQueue))

	return swi.Instance(ctx)
}

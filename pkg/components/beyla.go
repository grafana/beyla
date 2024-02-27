package components

import (
	"context"
	"log/slog"
	"os"

	"github.com/grafana/beyla/pkg/beyla"
	"github.com/grafana/beyla/pkg/internal/appolly"
	"github.com/grafana/beyla/pkg/internal/netolly/agent"
)

// StartBeyla in background
func StartBeyla(ctx context.Context, cfg *beyla.Config) {
	if cfg.Enabled(beyla.FeatureAppO11y) {
		go setupAppO11y(ctx, cfg)
	}
	if cfg.Enabled(beyla.FeatureNetO11y) {
		setupNetO11y(ctx, cfg)
	}
}

func setupAppO11y(ctx context.Context, config *beyla.Config) {
	slog.Info("starting Beyla in Application Observability mode")
	// TODO: when we split Beyla in two processes with different permissions, this code can be split:
	// in two parts:
	// 1st process (privileged) - Invoke FindTarget, which also mounts the BPF maps
	// 2nd executable (unprivileged) - Invoke ReadAndForward, receiving the BPF map mountpoint as argument

	instr := appolly.New(config)
	if err := instr.FindAndInstrument(ctx); err != nil {
		slog.Error("Beyla couldn't find target process", "error", err)
		os.Exit(-1)
	}
	if err := instr.ReadAndForward(ctx); err != nil {
		slog.Error("Beyla couldn't start read and forwarding", "error", err)
		os.Exit(-1)
	}
}

func setupNetO11y(ctx context.Context, cfg *beyla.Config) {
	slog.Info("starting Beyla in Network Observability mode")
	flowsAgent, err := agent.FlowsAgent(cfg)
	if err != nil {
		slog.Error("can't start network observability", "error", err)
		os.Exit(-1)
	}
	if err := flowsAgent.Run(ctx); err != nil {
		slog.Error("can't start network observability", "error", err)
		os.Exit(-1)
	}
}

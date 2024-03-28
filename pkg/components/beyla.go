package components

import (
	"context"
	"log/slog"
	"os"
	"sync"

	"github.com/grafana/beyla/pkg/beyla"
	"github.com/grafana/beyla/pkg/internal/appolly"
	"github.com/grafana/beyla/pkg/internal/connector"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/netolly/agent"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
)

// RunBeyla in the foreground process. This is a blocking function and won't exit
// until both the AppO11y and NetO11y components end
func RunBeyla(ctx context.Context, cfg *beyla.Config) {
	ctxInfo := buildCommonContextInfo(cfg)

	wg := sync.WaitGroup{}
	app := cfg.Enabled(beyla.FeatureAppO11y)
	if app {
		wg.Add(1)
	}
	net := cfg.Enabled(beyla.FeatureNetO11y)
	if net {
		wg.Add(1)
	}

	if app {
		go func() {
			defer wg.Done()
			setupAppO11y(ctx, ctxInfo, cfg)
		}()
	}
	if net {
		go func() {
			defer wg.Done()
			setupNetO11y(ctx, ctxInfo, cfg)
		}()
	}
	wg.Wait()
}

func setupAppO11y(ctx context.Context, ctxInfo *global.ContextInfo, config *beyla.Config) {
	slog.Info("starting Beyla in Application Observability mode")
	// TODO: when we split Beyla in two processes with different permissions, this code can be split:
	// in two parts:
	// 1st process (privileged) - Invoke FindTarget, which also mounts the BPF maps
	// 2nd executable (unprivileged) - Invoke ReadAndForward, receiving the BPF map mountpoint as argument

	instr := appolly.New(ctxInfo, config)
	if err := instr.FindAndInstrument(ctx); err != nil {
		slog.Error("Beyla couldn't find target process", "error", err)
		os.Exit(-1)
	}
	if err := instr.ReadAndForward(ctx); err != nil {
		slog.Error("Beyla couldn't start read and forwarding", "error", err)
		os.Exit(-1)
	}
}

func setupNetO11y(ctx context.Context, ctxInfo *global.ContextInfo, cfg *beyla.Config) {
	slog.Info("starting Beyla in Network metrics mode")
	flowsAgent, err := agent.FlowsAgent(ctxInfo, cfg)
	if err != nil {
		slog.Error("can't start network metrics capture", "error", err)
		os.Exit(-1)
	}
	if err := flowsAgent.Run(ctx); err != nil {
		slog.Error("can't start network metrics capture", "error", err)
		os.Exit(-1)
	}
}

// BuildContextInfo populates some globally shared components and properties
// from the user-provided configuration
func buildCommonContextInfo(
	config *beyla.Config,
) *global.ContextInfo {
	promMgr := &connector.PrometheusManager{}
	ctxInfo := &global.ContextInfo{
		Prometheus: promMgr,
		K8sEnabled: config.Attributes.Kubernetes.Enabled(),
	}
	if config.InternalMetrics.Prometheus.Port != 0 {
		slog.Debug("reporting internal metrics as Prometheus")
		ctxInfo.Metrics = imetrics.NewPrometheusReporter(&config.InternalMetrics.Prometheus, promMgr)
		// Prometheus manager also has its own internal metrics, so we need to pass the imetrics reporter
		// TODO: remove this dependency cycle and let prommgr to create and return the PrometheusReporter
		promMgr.InstrumentWith(ctxInfo.Metrics)
	} else {
		slog.Debug("not reporting internal metrics")
		ctxInfo.Metrics = imetrics.NoopReporter{}
	}
	return ctxInfo
}

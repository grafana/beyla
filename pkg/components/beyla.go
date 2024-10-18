package components

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/grafana/beyla/pkg/beyla"
	"github.com/grafana/beyla/pkg/export/attributes"
	"github.com/grafana/beyla/pkg/internal/appolly"
	"github.com/grafana/beyla/pkg/internal/connector"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/kube"
	"github.com/grafana/beyla/pkg/internal/netolly/agent"
	"github.com/grafana/beyla/pkg/internal/netolly/flow"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
)

// RunBeyla in the foreground process. This is a blocking function and won't exit
// until both the AppO11y and NetO11y components end
func RunBeyla(ctx context.Context, cfg *beyla.Config) error {
	ctxInfo := buildCommonContextInfo(ctx, cfg)

	wg := sync.WaitGroup{}
	app := cfg.Enabled(beyla.FeatureAppO11y)
	if app {
		wg.Add(1)
	}
	net := cfg.Enabled(beyla.FeatureNetO11y)
	if net {
		wg.Add(1)
	}

	errs := make(chan error, 2)
	if app {
		go func() {
			defer wg.Done()
			if err := setupAppO11y(ctx, ctxInfo, cfg); err != nil {
				errs <- err
			}
		}()
	}
	if net {
		go func() {
			defer wg.Done()
			if err := setupNetO11y(ctx, ctxInfo, cfg); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	select {
	case err := <-errs:
		return err
	default:
		return nil
	}
}

func setupAppO11y(ctx context.Context, ctxInfo *global.ContextInfo, config *beyla.Config) error {
	slog.Info("starting Beyla in Application Observability mode")
	instr := appolly.New(ctx, ctxInfo, config)
	if err := instr.FindAndInstrument(); err != nil {
		return fmt.Errorf("can't find target process: %w", err)
	}
	if err := instr.ReadAndForward(); err != nil {
		return fmt.Errorf("can't start read and forwarding: %w", err)
	}
	return nil
}

func setupNetO11y(ctx context.Context, ctxInfo *global.ContextInfo, cfg *beyla.Config) error {
	if msg := mustSkip(cfg); msg != "" {
		slog.Warn(msg + ". Skipping Network metrics component")
		return nil
	}
	slog.Info("starting Beyla in Network metrics mode")
	flowsAgent, err := agent.FlowsAgent(ctxInfo, cfg)
	if err != nil {
		return fmt.Errorf("can't start network metrics capture: %w", err)
	}
	if err := flowsAgent.Run(ctx); err != nil {
		return fmt.Errorf("can't start network metrics capture: %w", err)
	}
	return nil
}

func mustSkip(cfg *beyla.Config) string {
	enabled := cfg.Enabled(beyla.FeatureNetO11y)
	if !enabled {
		return "network not present neither in BEYLA_PROMETHEUS_FEATURES nor BEYLA_OTEL_METRICS_FEATURES"
	}
	return ""
}

// BuildContextInfo populates some globally shared components and properties
// from the user-provided configuration
func buildCommonContextInfo(
	ctx context.Context, config *beyla.Config,
) *global.ContextInfo {
	promMgr := &connector.PrometheusManager{}
	ctxInfo := &global.ContextInfo{
		Prometheus: promMgr,
		K8sInformer: kube.NewMetadataProvider(kube.MetadataConfig{
			Enable:            config.Attributes.Kubernetes.Enable,
			KubeConfigPath:    config.Attributes.Kubernetes.KubeconfigPath,
			SyncTimeout:       config.Attributes.Kubernetes.InformersSyncTimeout,
			ResyncPeriod:      config.Attributes.Kubernetes.InformersResyncPeriod,
			DisabledInformers: config.Attributes.Kubernetes.DisableInformers,
		}),
	}
	switch {
	case config.InternalMetrics.Prometheus.Port != 0:
		slog.Debug("reporting internal metrics as Prometheus")
		ctxInfo.Metrics = imetrics.NewPrometheusReporter(&config.InternalMetrics.Prometheus, promMgr, nil)
		// Prometheus manager also has its own internal metrics, so we need to pass the imetrics reporter
		// TODO: remove this dependency cycle and let prommgr to create and return the PrometheusReporter
		promMgr.InstrumentWith(ctxInfo.Metrics)
	case config.Prometheus.Registry != nil:
		slog.Debug("reporting internal metrics with Prometheus Registry")
		ctxInfo.Metrics = imetrics.NewPrometheusReporter(&config.InternalMetrics.Prometheus, nil, config.Prometheus.Registry)
	default:
		slog.Debug("not reporting internal metrics")
		ctxInfo.Metrics = imetrics.NoopReporter{}
	}

	attributeGroups(config, ctxInfo)

	if config.Attributes.HostID.Override == "" {
		ctxInfo.FetchHostID(ctx, config.Attributes.HostID.FetchTimeout)
	} else {
		ctxInfo.HostID = config.Attributes.HostID.Override
	}

	return ctxInfo
}

// attributeGroups specifies, based in the provided configuration, which groups of attributes
// need to be enabled by default for the diverse metrics
func attributeGroups(config *beyla.Config, ctxInfo *global.ContextInfo) {
	if ctxInfo.K8sInformer.IsKubeEnabled() {
		ctxInfo.MetricAttributeGroups.Add(attributes.GroupKubernetes)
	}
	if config.Routes != nil {
		ctxInfo.MetricAttributeGroups.Add(attributes.GroupHTTPRoutes)
	}
	if config.Metrics.ReportPeerInfo || config.Prometheus.ReportPeerInfo {
		ctxInfo.MetricAttributeGroups.Add(attributes.GroupPeerInfo)
	}
	if config.Metrics.ReportTarget || config.Prometheus.ReportTarget {
		ctxInfo.MetricAttributeGroups.Add(attributes.GroupTarget)
	}
	if config.NetworkFlows.Deduper == flow.DeduperNone {
		ctxInfo.MetricAttributeGroups.Add(attributes.GroupNetIfaceDirection)
	}
	if config.NetworkFlows.CIDRs.Enabled() {
		ctxInfo.MetricAttributeGroups.Add(attributes.GroupNetCIDR)
	}
}

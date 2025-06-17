package instrumenter

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"text/template"

	"golang.org/x/sync/errgroup"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/beyla"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/appolly"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/connector"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/imetrics"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/kube"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/netolly/agent"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/netolly/flow"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/pipe/global"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/otel"
)

// Run in the foreground process. This is a blocking function and won't exit
// until both the AppO11y and NetO11y components end
func Run(
	ctx context.Context, cfg *beyla.Config,
	opts ...Option,
) error {
	ctxInfo, err := buildCommonContextInfo(ctx, cfg)
	if err != nil {
		return fmt.Errorf("can't build common context info: %w", err)
	}
	for _, opt := range opts {
		opt(ctxInfo)
	}

	app := cfg.Enabled(beyla.FeatureAppO11y)
	net := cfg.Enabled(beyla.FeatureNetO11y)

	// if one of nodes fail, the other should stop
	g, ctx := errgroup.WithContext(ctx)

	if app {
		g.Go(func() error {
			if err := setupAppO11y(ctx, ctxInfo, cfg); err != nil {
				return fmt.Errorf("setupAppO11y: %w", err)
			}
			return nil
		})
	}

	if net {
		g.Go(func() error {
			if err := setupNetO11y(ctx, ctxInfo, cfg); err != nil {
				return fmt.Errorf("setupNetO11y: %w", err)
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}
	slog.Debug("OBI main node finished")
	return nil
}

func setupAppO11y(ctx context.Context, ctxInfo *global.ContextInfo, config *beyla.Config) error {
	slog.Info("starting Application Observability mode")

	instr, err := appolly.New(ctx, ctxInfo, config)
	if err != nil {
		slog.Debug("can't create new instrumenter", "error", err)
		return fmt.Errorf("can't create new instrumenter: %w", err)
	}

	if err := instr.FindAndInstrument(ctx); err != nil {
		slog.Debug("can't find target process", "error", err)
		return fmt.Errorf("can't find target process: %w", err)
	}

	if err := instr.ReadAndForward(ctx); err != nil {
		slog.Debug("read and forward auto-instrumenter", "error", err)
		return err
	}

	if err := instr.WaitUntilFinished(); err != nil {
		slog.Error("waiting for App O11y pipeline to finish", "error", err)
		return err
	}

	slog.Debug("Application O11y pipeline finished")
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
		slog.Debug("can't start network metrics capture", "error", err)
		return fmt.Errorf("can't start network metrics capture: %w", err)
	}

	err = flowsAgent.Run(ctx)
	if err != nil {
		slog.Debug("can't run network metrics capture", "error", err)
		return fmt.Errorf("can't run network metrics capture: %w", err)
	}

	return nil
}

func mustSkip(cfg *beyla.Config) string {
	enabled := cfg.Enabled(beyla.FeatureNetO11y)
	if !enabled {
		return "network not present neither in OTEL_EBPF_PROMETHEUS_FEATURES nor OTEL_EBPF_OTEL_METRICS_FEATURES"
	}
	return ""
}

func buildServiceNameTemplate(config *beyla.Config) (*template.Template, error) {
	var templ *template.Template

	if config.Attributes.Kubernetes.ServiceNameTemplate != "" {
		var err error

		templ, err = template.New("serviceNameTemplate").Parse(config.Attributes.Kubernetes.ServiceNameTemplate)
		if err != nil {
			return nil, fmt.Errorf("unable to parse service name template: %w", err)
		}
	}

	return templ, nil
}

// BuildContextInfo populates some globally shared components and properties
// from the user-provided configuration
func buildCommonContextInfo(
	ctx context.Context, config *beyla.Config,
) (*global.ContextInfo, error) {
	// merging deprecated resource labels definition for backwards compatibility
	resourceLabels := config.Attributes.Kubernetes.ResourceLabels
	if resourceLabels == nil {
		resourceLabels = map[string][]string{}
	}
	showDeprecation := sync.OnceFunc(func() {
		slog.Warn("The meta_source_labels (OTEL_EBPF_KUBE_META_SOURCE_LABEL_* environment variables) is deprecated." +
			" Check the documentation for more information about replacing it by the resource_labels kubernetes" +
			" YAML property")
	})
	if svc := config.Attributes.Kubernetes.MetaSourceLabels.ServiceName; svc != "" {
		resourceLabels["service.name"] = append([]string{svc}, resourceLabels["service.name"]...)
		showDeprecation()
	}
	if ns := config.Attributes.Kubernetes.MetaSourceLabels.ServiceNamespace; ns != "" {
		resourceLabels["service.namespace"] = append([]string{ns}, resourceLabels["service.namespace"]...)
		showDeprecation()
	}

	templ, err := buildServiceNameTemplate(config)
	if err != nil {
		return nil, err
	}

	promMgr := &connector.PrometheusManager{}
	ctxInfo := &global.ContextInfo{
		Prometheus: promMgr,
		K8sInformer: kube.NewMetadataProvider(kube.MetadataConfig{
			Enable:              config.Attributes.Kubernetes.Enable,
			KubeConfigPath:      config.Attributes.Kubernetes.KubeconfigPath,
			SyncTimeout:         config.Attributes.Kubernetes.InformersSyncTimeout,
			ResyncPeriod:        config.Attributes.Kubernetes.InformersResyncPeriod,
			DisabledInformers:   config.Attributes.Kubernetes.DisableInformers,
			MetaCacheAddr:       config.Attributes.Kubernetes.MetaCacheAddress,
			ResourceLabels:      resourceLabels,
			RestrictLocalNode:   config.Attributes.Kubernetes.MetaRestrictLocalNode,
			ServiceNameTemplate: templ,
		}),
	}
	if config.Attributes.HostID.Override == "" {
		ctxInfo.FetchHostID(ctx, config.Attributes.HostID.FetchTimeout)
	} else {
		ctxInfo.HostID = config.Attributes.HostID.Override
	}
	switch {
	case config.InternalMetrics.Exporter == imetrics.InternalMetricsExporterOTEL:
		var err error
		slog.Debug("reporting internal metrics as OpenTelemetry")
		ctxInfo.Metrics, err = otel.NewInternalMetricsReporter(ctx, ctxInfo, &config.Metrics)
		if err != nil {
			return nil, fmt.Errorf("can't start OpenTelemetry metrics: %w", err)
		}
	case config.InternalMetrics.Exporter == imetrics.InternalMetricsExporterPrometheus || config.InternalMetrics.Prometheus.Port != 0:
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

	return ctxInfo, nil
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
	if config.NetworkFlows.Deduper == flow.DeduperNone {
		ctxInfo.MetricAttributeGroups.Add(attributes.GroupNetIfaceDirection)
	}
	if config.NetworkFlows.CIDRs.Enabled() {
		ctxInfo.MetricAttributeGroups.Add(attributes.GroupNetCIDR)
	}
}

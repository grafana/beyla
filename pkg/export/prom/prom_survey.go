package prom

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/mariomac/pipes/pipe"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/beyla/v2/pkg/buildinfo"
	"github.com/grafana/beyla/v2/pkg/export/attributes"
	attr "github.com/grafana/beyla/v2/pkg/export/attributes/names"
	"github.com/grafana/beyla/v2/pkg/export/expire"
	"github.com/grafana/beyla/v2/pkg/export/otel"
	"github.com/grafana/beyla/v2/pkg/internal/connector"
	"github.com/grafana/beyla/v2/pkg/internal/pipe/global"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"
)

// injectable function reference for testing

// SurveyPrometheusConfig for survey metrics just wraps the global PrometheusConfig as provided by the user
type SurveyPrometheusConfig struct {
	Metrics            *PrometheusConfig
	AttributeSelectors attributes.Selection
}

// nolint:gocritic
func (p SurveyPrometheusConfig) Enabled() bool {
	return p.Metrics != nil && (p.Metrics.Port != 0 || p.Metrics.Registry != nil) && p.Metrics.OTelMetricsEnabled()
}

// SurveyPrometheusEndpoint provides a pipeline node that export the survey information as
// prometheus metrics
func SurveyPrometheusEndpoint(
	ctx context.Context, ctxInfo *global.ContextInfo, cfg *SurveyPrometheusConfig,
) pipe.FinalProvider[[]otel.SurveyInfo] {
	return func() (pipe.FinalFunc[[]otel.SurveyInfo], error) {
		if !cfg.Enabled() {
			// This node is not going to be instantiated. Let the pipes library just ignore it.
			return pipe.IgnoreFinal[[]otel.SurveyInfo](), nil
		}
		reporter, err := newSurveyReporter(ctx, ctxInfo, cfg)
		if err != nil {
			return nil, err
		}
		if cfg.Metrics.Registry != nil {
			return reporter.collectMetrics, nil
		}
		return reporter.reportMetrics, nil
	}
}

type surveyMetricsReporter struct {
	cfg *PrometheusConfig

	promConnect *connector.PrometheusManager

	clock  *expire.CachedClock
	bgCtx  context.Context
	hostID string

	// metrics
	surveyedAttrs []attributes.Field[otel.SurveyInfo, string]
	surveyed      *Expirer[prometheus.Gauge]
	processMap    map[int32][]string
}

func newSurveyReporter(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *SurveyPrometheusConfig,
) (*surveyMetricsReporter, error) {
	group := ctxInfo.MetricAttributeGroups
	// this property can't be set inside the ConfiguredGroups function, otherwise the
	// OTEL exporter would report also some prometheus-exclusive attributes
	group.Add(attributes.GroupPrometheus)

	provider, err := attributes.NewAttrSelector(group, cfg.AttributeSelectors)
	if err != nil {
		return nil, fmt.Errorf("network Prometheus exporter attributes enable: %w", err)
	}

	surveyAttrNames := provider.For(attributes.SurveyInfo)
	surveyAttrNames = otherSurveyAttributes(surveyAttrNames)

	clock := expire.NewCachedClock(timeNow)
	// If service name is not explicitly set, we take the service name as set by the
	// executable inspector
	mr := &surveyMetricsReporter{
		bgCtx:       ctx,
		cfg:         cfg.Metrics,
		promConnect: ctxInfo.Prometheus,
		clock:       clock,
		hostID:      ctxInfo.HostID,
		processMap:  map[int32][]string{},
	}

	surveyGetters := attributes.PrometheusGetters(mr.surveyGetters, surveyAttrNames)

	surveyLabelNames := []string{}
	for _, label := range surveyGetters {
		surveyLabelNames = append(surveyLabelNames, label.ExposedName)
	}

	mr.surveyedAttrs = surveyGetters
	mr.surveyed = NewExpirer[prometheus.Gauge](prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: attributes.SurveyInfo.Prom,
		Help: "List of services discovered on the node",
	}, surveyLabelNames).MetricVec, clock.Time, 360000*time.Hour)

	if cfg.Metrics.Registry != nil {
		cfg.Metrics.Registry.MustRegister(mr.surveyed)
	} else {
		mr.promConnect.Register(cfg.Metrics.Port, cfg.Metrics.Path, mr.surveyed)
	}

	return mr, nil
}

func (r *surveyMetricsReporter) reportMetrics(input <-chan []otel.SurveyInfo) {
	go r.promConnect.StartHTTP(r.bgCtx)
	r.collectMetrics(input)
}

func (r *surveyMetricsReporter) collectMetrics(input <-chan []otel.SurveyInfo) {
	for processes := range input {
		// clock needs to be updated to let the expirer
		// remove the old metrics
		r.clock.Update()
		for _, proc := range processes {
			r.observeMetric(proc)
		}
	}
}

func (r *surveyMetricsReporter) observeMetric(s otel.SurveyInfo) {
	if s.Type == otel.EventDeleted {
		if vals, ok := r.processMap[s.File.Pid]; ok {
			fmt.Printf("Deleting metrics for %d, [%v]\n", s.File.Pid, vals)
			r.surveyed.entries.DeleteSelected(vals)
			delete(r.processMap, s.File.Pid)
		}
	} else {
		vals := labelValues(s, r.surveyedAttrs)
		r.processMap[s.File.Pid] = vals
		r.surveyed.WithLabelValues(vals...).metric.Set(float64(1))
	}
}

func (r *surveyMetricsReporter) surveyGetters(name attr.Name) (attributes.Getter[otel.SurveyInfo, string], bool) {
	var g attributes.Getter[otel.SurveyInfo, string]
	switch name {
	case attr.HostName:
		g = func(s otel.SurveyInfo) string { return s.File.Service.HostName }
	case attr.HostID:
		g = func(s otel.SurveyInfo) string { return r.hostID }
	case attr.ProcCommandLine:
		g = func(s otel.SurveyInfo) string { return s.File.CmdLine }
	case attr.ProcCommand:
		g = func(s otel.SurveyInfo) string { return s.File.CmdExePath }
	case attr.ProcPid:
		g = func(s otel.SurveyInfo) string { return strconv.Itoa(int(s.File.Pid)) }
	case attr.Instance:
		g = func(s otel.SurveyInfo) string { return s.File.Service.UID.Instance }
	case attr.Name(semconv.ServiceInstanceIDKey):
		g = func(s otel.SurveyInfo) string { return s.File.Service.UID.Instance }
	case attr.Name(semconv.TelemetrySDKLanguageKey):
		g = func(s otel.SurveyInfo) string { return s.File.Service.SDKLanguage.String() }
	case attr.Name(semconv.TelemetrySDKNameKey):
		g = func(s otel.SurveyInfo) string { return "beyla" }
	case attr.Name(semconv.TelemetrySDKVersionKey):
		g = func(s otel.SurveyInfo) string { return buildinfo.Version }
	case attr.Name(semconv.OSTypeKey):
		g = func(s otel.SurveyInfo) string { return "linux" }
	case attr.ServiceName:
		g = func(s otel.SurveyInfo) string { return s.File.Service.UID.Name }
	case attr.ServiceNamespace:
		g = func(s otel.SurveyInfo) string { return s.File.Service.UID.Namespace }
	case attr.Job:
		g = func(s otel.SurveyInfo) string { return s.File.Service.Job() }
	default:
		g = func(s otel.SurveyInfo) string { return s.File.Service.Metadata[name] }
	}
	return g, g != nil
}

func otherSurveyAttributes(attrs []attr.Name) []attr.Name {
	attrs = append(attrs,
		attr.ServerNamespace, attr.HostID, attr.Instance,
		attr.Name(semconv.TelemetrySDKLanguageKey), attr.Name(semconv.TelemetrySDKNameKey), attr.Name(semconv.TelemetrySDKVersionKey),
		attr.Name(semconv.ServiceInstanceIDKey), attr.ProcCommand, attr.ProcCommandLine,
		attr.Name(semconv.OSTypeKey),
	)

	return attrs
}

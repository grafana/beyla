package otel

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/mariomac/pipes/pipe"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"

	"github.com/grafana/beyla/v2/pkg/export/attributes"
	attr "github.com/grafana/beyla/v2/pkg/export/attributes/names"
	"github.com/grafana/beyla/v2/pkg/export/expire"
	"github.com/grafana/beyla/v2/pkg/export/otel/metric"
	metric2 "github.com/grafana/beyla/v2/pkg/export/otel/metric/api/metric"
	"github.com/grafana/beyla/v2/pkg/internal/exec"
	"github.com/grafana/beyla/v2/pkg/internal/helpers/container"
	"github.com/grafana/beyla/v2/pkg/internal/pipe/global"
	"github.com/grafana/beyla/v2/pkg/internal/svc"
)

type SurveyEventType int

const (
	EventCreated = SurveyEventType(iota)
	EventDeleted
)

type SurveyInfo struct {
	File  *exec.FileInfo
	Type  SurveyEventType
	CInfo container.Info
}

type SurveyMetricsConfig struct {
	Metrics            *MetricsConfig
	AttributeSelectors attributes.Selection
}

func (mc *SurveyMetricsConfig) Enabled() bool {
	return mc.Metrics != nil && mc.Metrics.EndpointEnabled() && mc.Metrics.OTelMetricsEnabled()
}

func smlog() *slog.Logger {
	return slog.With("component", "otel.SurveyMetricsExporter")
}

type surveyMetricsExporter struct {
	ctx   context.Context
	cfg   *SurveyMetricsConfig
	clock *expire.CachedClock

	hostID string

	exporter  sdkmetric.Exporter
	reporters ReporterPool[*exec.FileInfo, *surveyMetrics]

	log *slog.Logger

	attrSurveyed []attributes.Field[*exec.FileInfo, attribute.KeyValue]
	processMap   map[int32]attribute.Set
}

type surveyMetrics struct {
	ctx      context.Context
	provider *metric.MeterProvider

	// don't forget to add the cleanup code in cleanupAllMetricsInstances function
	surveyed *Expirer[*exec.FileInfo, metric2.Int64Gauge, float64]
}

func SurveyMetricsExporterProvider(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *SurveyMetricsConfig,
) pipe.FinalProvider[[]SurveyInfo] {
	return func() (pipe.FinalFunc[[]SurveyInfo], error) {
		if !cfg.Enabled() {
			// This node is not going to be instantiated. Let the pipes library just ignore it.
			return pipe.IgnoreFinal[[]SurveyInfo](), nil
		}
		return newSurveyMetricsExporter(ctx, ctxInfo, cfg)
	}
}

func SurveyNoopExporterProvider() pipe.FinalProvider[[]SurveyInfo] {
	return func() (pipe.FinalFunc[[]SurveyInfo], error) {
		return Noop, nil
	}
}

func surveyGetters(name attr.Name) (attributes.Getter[*exec.FileInfo, attribute.KeyValue], bool) {
	var g attributes.Getter[*exec.FileInfo, attribute.KeyValue]
	switch name {
	case attr.ProcPid:
		g = func(fi *exec.FileInfo) attribute.KeyValue {
			return attribute.Int(string(attr.ProcPid), int(fi.Pid))
		}
	case attr.Job:
		g = func(fi *exec.FileInfo) attribute.KeyValue {
			return attribute.String(string(attr.Job), fi.Service.Job())
		}
	case attr.ServiceName:
		g = func(fi *exec.FileInfo) attribute.KeyValue {
			return attribute.String(string(attr.ServiceName), fi.Service.UID.Name)
		}
	case attr.ServiceNamespace:
		g = func(fi *exec.FileInfo) attribute.KeyValue {
			return attribute.String(string(attr.ServiceNamespace), fi.Service.UID.Namespace)
		}
	}
	return g, g != nil
}

func newSurveyMetricsExporter(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *SurveyMetricsConfig,
) (pipe.FinalFunc[[]SurveyInfo], error) {
	SetupInternalOTELSDKLogger(cfg.Metrics.SDKLogLevel)

	log := smlog()
	log.Debug("instantiating survey metrics exporter provider")

	// only user-provided attributes (or default set) will decorate the metrics
	attrProv, err := attributes.NewAttrSelector(ctxInfo.MetricAttributeGroups, cfg.AttributeSelectors)
	if err != nil {
		return nil, fmt.Errorf("survey OTEL exporter attributes: %w", err)
	}

	surveyNames := attrProv.For(attributes.SurveyInfo)
	attrSurvey := attributes.OpenTelemetryGetters(surveyGetters, surveyNames)

	mr := &surveyMetricsExporter{
		log:          log,
		ctx:          ctx,
		cfg:          cfg,
		hostID:       ctxInfo.HostID,
		clock:        expire.NewCachedClock(timeNow),
		attrSurveyed: attrSurvey,
		processMap:   map[int32]attribute.Set{},
	}

	mr.reporters = NewReporterPool(cfg.Metrics.ReportersCacheLen, 360000*time.Hour, timeNow,
		func(id svc.UID, v *expirable[*surveyMetrics]) {
			llog := log.With("service", id)
			llog.Debug("evicting metrics reporter from cache")
			v.value.cleanupAllMetricsInstances()
			go func() {
				if err := v.value.provider.ForceFlush(ctx); err != nil {
					llog.Warn("error flushing evicted metrics provider", "error", err)
				}
			}()
		}, mr.newMetricSet)

	mr.exporter, err = InstantiateMetricsExporter(ctx, cfg.Metrics, log)
	if err != nil {
		log.Error("instantiating metrics exporter", "error", err)
		return nil, err
	}

	return mr.Do, nil
}

func (me *surveyMetricsExporter) newMetricSet(f *exec.FileInfo) (*surveyMetrics, error) {
	log := me.log.With("service", f.Service, "processID", f.Service.UID)
	log.Debug("creating new Metrics exporter")
	resources := resource.NewWithAttributes(semconv.SchemaURL, getSurveyResourceAttrs(f)...)
	opts := []metric.Option{
		metric.WithResource(resources),
		metric.WithReader(metric.NewPeriodicReader(me.exporter,
			metric.WithInterval(me.cfg.Metrics.Interval))),
	}

	m := surveyMetrics{
		ctx:      me.ctx,
		provider: metric.NewMeterProvider(opts...),
	}

	meter := m.provider.Meter(reporterName)

	if surveyed, err := meter.Int64Gauge(
		attributes.SurveyInfo.OTEL, metric2.WithDescription("Surveyed processes"),
	); err != nil {
		log.Error("creating observable gauge for "+attributes.SurveyInfo.OTEL, "error", err)
		return nil, err
	} else {
		m.surveyed = NewExpirer[*exec.FileInfo, metric2.Int64Gauge, float64](
			me.ctx, surveyed, me.attrSurveyed, timeNow, 360000*time.Hour)
	}

	return &m, nil
}

// Do reads all the process status data points and create the metrics accordingly
func (me *surveyMetricsExporter) Do(in <-chan []SurveyInfo) {
	for i := range in {
		me.clock.Update()
		for _, e := range i {
			reporter, err := me.reporters.For(e.File)
			if err != nil {
				me.log.Error("unexpected error creating OTEL resource. Ignoring metric",
					"error", err, "service", e.File.Service)
				continue
			}
			me.observeMetric(reporter, &e)
		}
	}
}

func Noop(in <-chan []SurveyInfo) {
	for i := range in {
		slog.Debug("survey info", "info", i)
	}
}

func getSurveyResourceAttrs(f *exec.FileInfo) []attribute.KeyValue {
	return []attribute.KeyValue{
		attr.ServiceName.OTEL().String(f.Service.UID.Name),
		attr.ServiceNamespace.OTEL().String(f.Service.UID.Namespace),
	}
}

func getSurveyAttrs(hostID string, f *exec.FileInfo) []attribute.KeyValue {
	return append(
		getResourceAttrs(hostID, &f.Service),
		semconv.ServiceInstanceID(f.Service.UID.Instance),
		attr.ProcCommand.OTEL().String(f.CmdExePath),
		attr.ProcPid.OTEL().String(strconv.Itoa(int(f.Pid))),
		attr.ProcCommandLine.OTEL().String(f.CmdLine),
		attr.Instance.OTEL().String(f.Service.UID.Instance),
	)
}

func (me *surveyMetricsExporter) observeMetric(reporter *surveyMetrics, s *SurveyInfo) {
	mr, attrs := reporter.surveyed.ForRecord(s.File, getSurveyAttrs(me.hostID, s.File)...)
	if s.Type == EventCreated {
		me.processMap[s.File.Pid] = attrs
		mr.Record(reporter.ctx, 1, metric2.WithAttributeSet(attrs))
	} else {
		if savedAttrs, ok := me.processMap[s.File.Pid]; ok {
			mr.Remove(reporter.ctx, metric2.WithAttributeSet(savedAttrs))
			delete(me.processMap, s.File.Pid)
		}
	}
}

func (r *surveyMetrics) cleanupAllMetricsInstances() {
	r.surveyed.RemoveAllMetrics(r.ctx)
}

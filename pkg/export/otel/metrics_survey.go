package otel

import (
	"context"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/exec"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/svc"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/swarm"

	"github.com/grafana/beyla/v2/pkg/export/otel/metric"
	instrument "github.com/grafana/beyla/v2/pkg/export/otel/metric/api/metric"
	"github.com/grafana/beyla/v2/pkg/internal/pipe/global"
)

func smlog() *slog.Logger {
	return slog.With("component", "otel.SurveyMetricsReporter")
}

type SurveyMetricsReporter struct {
	log *slog.Logger
	cfg *MetricsConfig

	provider *metric.MeterProvider

	surveyInfo instrument.Int64UpDownCounter

	hostID        string
	processEvents <-chan exec.ProcessEvent
	exporter      sdkmetric.Exporter
	pidTracker    PidServiceTracker
	serviceMap    map[svc.UID][]attribute.KeyValue
}

func SurveyInfoMetrics(
	ctxInfo *global.ContextInfo,
	cfg *MetricsConfig,
	processEventCh *msg.Queue[exec.ProcessEvent],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled() {
			return swarm.EmptyRunFunc()
		}
		SetupInternalOTELSDKLogger(cfg.SDKLogLevel)

		mr, err := newSurveyMetricsReporter(ctx, ctxInfo, cfg, processEventCh)
		if err != nil {
			return nil, fmt.Errorf("instantiating OTEL metrics reporter: %w", err)
		}

		return mr.watchForProcessEvents, nil
	}
}

func newSurveyMetricsReporter(
	ctx context.Context, ctxInfo *global.ContextInfo, cfg *MetricsConfig,
	processEventsQueue *msg.Queue[exec.ProcessEvent],
) (*SurveyMetricsReporter, error) {
	log := smlog()
	smr := &SurveyMetricsReporter{
		log:           log,
		cfg:           cfg,
		hostID:        ctxInfo.HostID,
		serviceMap:    map[svc.UID][]attribute.KeyValue{},
		processEvents: processEventsQueue.Subscribe(),
		pidTracker:    NewPidServiceTracker(),
	}
	log.Debug("creating new Survey Metrics reporter")

	var err error
	smr.exporter, err = InstantiateMetricsExporter(ctx, cfg, log)
	if err != nil {
		return nil, fmt.Errorf("instantiating OTEL Survey metrics exporter: %w", err)
	}

	smr.provider = metric.NewMeterProvider(
		metric.WithResource(resource.Empty()),
		metric.WithReader(metric.NewPeriodicReader(smr.exporter,
			metric.WithInterval(smr.cfg.Interval))),
	)
	meter := smr.provider.Meter(reporterName)
	smr.surveyInfo, err = meter.Int64UpDownCounter(SurveyInfo)
	if err != nil {
		return nil, fmt.Errorf("creating survey info: %w", err)
	}

	return smr, nil
}

func (smr *SurveyMetricsReporter) watchForProcessEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case pe, ok := <-smr.processEvents:
			if !ok {
				return
			}

			log := smr.log.With("event_type", pe.Type, "pid", pe.File.Pid, "attrs", pe.File.Service.UID)
			log.Debug("process event received")

			switch pe.Type {
			case exec.ProcessEventTerminated:
				if deleted, origUID := smr.disassociatePIDFromService(pe.File.Pid); deleted {
					// We only need the UID to look up in the pool, no need to cache
					// the whole of the attrs in the pidTracker
					svc := svc.Attrs{UID: origUID}
					log.Debug("deleting survey_info", "origuid", origUID)
					smr.deleteSurveyInfo(ctx, &svc)
				}
			case exec.ProcessEventCreated:
				smr.createSurveyInfo(ctx, &pe.File.Service)
				smr.setupPIDToServiceRelationship(pe.File.Pid, pe.File.Service.UID)
			}
		}
	}
}

func (smr *SurveyMetricsReporter) setupPIDToServiceRelationship(pid int32, uid svc.UID) {
	smr.pidTracker.AddPID(pid, uid)
}

func (smr *SurveyMetricsReporter) disassociatePIDFromService(pid int32) (bool, svc.UID) {
	return smr.pidTracker.RemovePID(pid)
}

func (smr *SurveyMetricsReporter) createSurveyInfo(ctx context.Context, service *svc.Attrs) {
	resourceAttributes := append(getAppResourceAttrs(smr.hostID, service), ResourceAttrsFromEnv(service)...)
	smr.log.Debug("Creating survey_info", "attrs", resourceAttributes)
	attrOpt := instrument.WithAttributeSet(attribute.NewSet(resourceAttributes...))
	smr.surveyInfo.Add(ctx, 1, attrOpt)
	smr.serviceMap[service.UID] = resourceAttributes
}

func (smr *SurveyMetricsReporter) deleteSurveyInfo(ctx context.Context, s *svc.Attrs) {
	attrs, ok := smr.serviceMap[s.UID]
	if !ok {
		smr.log.Debug("No service map", "UID", s.UID)
		return
	}
	smr.log.Debug("Deleting survey_info for", "attrs", attrs)
	attrOpt := instrument.WithAttributeSet(attribute.NewSet(attrs...))
	smr.surveyInfo.Remove(ctx, attrOpt)
	delete(smr.serviceMap, s.UID)
}

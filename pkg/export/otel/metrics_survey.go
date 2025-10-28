package otel

import (
	"context"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/export/otel/metric"
	instrument "go.opentelemetry.io/obi/pkg/export/otel/metric/api/metric"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

func smlog() *slog.Logger {
	return slog.With("component", "otel.SurveyMetricsReporter")
}

type SurveyMetricsReporter struct {
	log *slog.Logger
	cfg *otelcfg.MetricsConfig

	provider *metric.MeterProvider

	surveyInfo instrument.Int64UpDownCounter

	hostID        string
	processEvents <-chan exec.ProcessEvent
	exporter      sdkmetric.Exporter
	pidTracker    otel.PidServiceTracker
	serviceMap    map[svc.UID][]attribute.KeyValue

	// testing support
	createEventMetrics func(ctx context.Context, service *svc.Attrs)
	deleteEventMetrics func(ctx context.Context, uid svc.UID)
}

func SurveyInfoMetrics(
	ctxInfo *global.ContextInfo,
	cfg *otelcfg.MetricsConfig,
	processEventCh *msg.Queue[exec.ProcessEvent],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled() {
			return swarm.EmptyRunFunc()
		}
		otelcfg.SetupInternalOTELSDKLogger(cfg.SDKLogLevel)

		mr, err := newSurveyMetricsReporter(ctx, ctxInfo, cfg, processEventCh)
		if err != nil {
			return nil, fmt.Errorf("instantiating OTEL metrics reporter: %w", err)
		}

		return mr.watchForProcessEvents, nil
	}
}

func newSurveyMetricsReporter(
	ctx context.Context, ctxInfo *global.ContextInfo, cfg *otelcfg.MetricsConfig,
	processEventsQueue *msg.Queue[exec.ProcessEvent],
) (*SurveyMetricsReporter, error) {
	log := smlog()
	smr := &SurveyMetricsReporter{
		log:           log,
		cfg:           cfg,
		hostID:        ctxInfo.HostID,
		serviceMap:    map[svc.UID][]attribute.KeyValue{},
		processEvents: processEventsQueue.Subscribe(msg.SubscriberName("processEvents")),
		pidTracker:    otel.NewPidServiceTracker(),
	}
	log.Debug("creating new Survey Metrics reporter")

	var err error
	smr.exporter, err = ctxInfo.OTELMetricsExporter.Instantiate(ctx)
	if err != nil {
		return nil, fmt.Errorf("instantiating OTEL Survey metrics exporter: %w", err)
	}

	smr.createEventMetrics = smr.createSurveyInfo
	smr.deleteEventMetrics = smr.deleteSurveyInfo

	smr.provider = metric.NewMeterProvider(
		metric.WithResource(resource.Empty()),
		metric.WithReader(metric.NewPeriodicReader(smr.exporter,
			metric.WithInterval(smr.cfg.Interval))),
	)
	meter := smr.provider.Meter(ReporterName)
	smr.surveyInfo, err = meter.Int64UpDownCounter(SurveyInfo)
	if err != nil {
		return nil, fmt.Errorf("creating survey info: %w", err)
	}

	return smr, nil
}

func (smr *SurveyMetricsReporter) onProcessEvent(ctx context.Context, pe *exec.ProcessEvent) {
	log := smr.log.With("event_type", pe.Type, "pid", pe.File.Pid, "attrs", pe.File.Service.UID)
	log.Debug("process event received")

	switch pe.Type {
	case exec.ProcessEventTerminated:
		if deleted, origUID := smr.disassociatePIDFromService(pe.File.Pid); deleted {
			// We only need the UID to look up in the pool, no need to cache
			// the whole of the attrs in the pidTracker
			log.Debug("deleting survey_info", "origuid", origUID)
			smr.deleteEventMetrics(ctx, origUID)
		}
	case exec.ProcessEventCreated:
		uid := pe.File.Service.UID

		// Handle the case when the PID changed its feathers, e.g. got new metadata impacting the service name.
		// There's no new PID, just an update to the metadata.
		if staleUID, exists := smr.pidTracker.TracksPID(pe.File.Pid); exists && !staleUID.Equals(&uid) {
			smr.log.Debug("updating older service definition", "from", staleUID, "new", uid)
			smr.pidTracker.ReplaceUID(staleUID, uid)
			smr.deleteEventMetrics(ctx, staleUID)
			smr.createEventMetrics(ctx, &pe.File.Service)
			// we don't setup the pid again, we just replaced the metrics it's associated with
			return
		}

		// Handle the case when we have new labels for same service
		// It could be a brand new PID with this information, so we fall through after deleting
		// the old target info
		if _, ok := smr.serviceMap[uid]; ok {
			smr.log.Debug("updating stale attributes for", "service", uid)
			smr.deleteEventMetrics(ctx, uid)
		}

		smr.createEventMetrics(ctx, &pe.File.Service)
		smr.setupPIDToServiceRelationship(pe.File.Pid, pe.File.Service.UID)
	}
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

			smr.onProcessEvent(ctx, &pe)
		}
	}
}

func (smr *SurveyMetricsReporter) setupPIDToServiceRelationship(pid int32, uid svc.UID) {
	smr.pidTracker.AddPID(pid, uid)
}

func (smr *SurveyMetricsReporter) disassociatePIDFromService(pid int32) (bool, svc.UID) {
	return smr.pidTracker.RemovePID(pid)
}

func (smr *SurveyMetricsReporter) attrsFromService(service *svc.Attrs) []attribute.KeyValue {
	return append(otelcfg.GetAppResourceAttrs(smr.hostID, service), otelcfg.ResourceAttrsFromEnv(service)...)
}

func (smr *SurveyMetricsReporter) createSurveyInfo(ctx context.Context, service *svc.Attrs) {
	resourceAttributes := smr.attrsFromService(service)
	smr.log.Debug("Creating survey_info", "attrs", resourceAttributes)
	attrOpt := instrument.WithAttributeSet(attribute.NewSet(resourceAttributes...))
	smr.surveyInfo.Add(ctx, 1, attrOpt)
	smr.serviceMap[service.UID] = resourceAttributes
}

func (smr *SurveyMetricsReporter) deleteSurveyInfo(ctx context.Context, uid svc.UID) {
	attrs, ok := smr.serviceMap[uid]
	if !ok {
		smr.log.Debug("No service map", "UID", uid)
		return
	}
	smr.log.Debug("Deleting survey_info for", "attrs", attrs)
	attrOpt := instrument.WithAttributeSet(attribute.NewSet(attrs...))
	smr.surveyInfo.Remove(ctx, attrOpt)
	delete(smr.serviceMap, uid)
}

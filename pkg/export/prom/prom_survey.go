package prom

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/connector"
	"go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

const (
	SurveyInfo = "survey_info"
)

func pslog() *slog.Logger {
	return slog.With("component", "prom.SurveyMetricsReporter")
}

type surveyMetricsReporter struct {
	processEvents <-chan exec.ProcessEvent

	surveyInfo *prometheus.GaugeVec

	promConnect *connector.PrometheusManager

	hostID string

	serviceMap  map[svc.UID]svc.Attrs
	pidsTracker otel.PidServiceTracker

	kubeEnabled         bool
	extraMetadataLabels []attr.Name

	// for testing purposes
	createEventMetrics func(service *svc.Attrs)
	deleteEventMetrics func(uid svc.UID, service *svc.Attrs)
}

func SurveyPrometheusEndpoint(
	ctxInfo *global.ContextInfo,
	cfg *prom.PrometheusConfig,
	processEventCh *msg.Queue[exec.ProcessEvent],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if !cfg.EndpointEnabled() {
			return swarm.EmptyRunFunc()
		}
		reporter, err := newSurveyReporter(ctxInfo, cfg, processEventCh)
		if err != nil {
			return nil, fmt.Errorf("instantiating Prometheus endpoint: %w", err)
		}
		if cfg.Registry != nil {
			return reporter.watchForProcessEvents, nil
		}
		return reporter.reportMetrics, nil
	}
}

// nolint:cyclop
func newSurveyReporter(
	ctxInfo *global.ContextInfo,
	cfg *prom.PrometheusConfig,
	processEventCh *msg.Queue[exec.ProcessEvent],
) (*surveyMetricsReporter, error) {

	kubeEnabled := ctxInfo.K8sInformer.IsKubeEnabled()
	extraMetadataLabels := parseExtraMetadata(cfg.ExtraResourceLabels)

	mr := &surveyMetricsReporter{
		processEvents: processEventCh.Subscribe(msg.SubscriberName("processEvents")),
		serviceMap:    map[svc.UID]svc.Attrs{},
		pidsTracker:   otel.NewPidServiceTracker(),
		hostID:        ctxInfo.HostID,
		promConnect:   ctxInfo.Prometheus,
		surveyInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: SurveyInfo,
			Help: "attributes associated to a given surveyed entity",
		}, labelNamesTargetInfo(kubeEnabled, extraMetadataLabels)),
		extraMetadataLabels: extraMetadataLabels,
		kubeEnabled:         kubeEnabled,
	}

	// testing aid
	mr.deleteEventMetrics = mr.deleteSurveyInfo
	mr.createEventMetrics = mr.createSurveyInfo

	if cfg.Registry != nil {
		cfg.Registry.MustRegister(mr.surveyInfo)
	} else {
		mr.promConnect.Register(cfg.Port, cfg.Path, mr.surveyInfo)
	}

	return mr, nil
}

func (r *surveyMetricsReporter) reportMetrics(ctx context.Context) {
	go r.promConnect.StartHTTP(ctx)
	r.watchForProcessEvents(ctx)
}

func (r *surveyMetricsReporter) labelValues(service *svc.Attrs) []string {
	values := []string{
		r.hostID,
		service.HostName,
		service.UID.Name,
		service.UID.Namespace,
		service.UID.Instance, // app instance ID
		service.Job(),
		service.SDKLanguage.String(),
		"beyla",
		"beyla",
		"linux",
	}

	if r.kubeEnabled {
		values = appendK8sLabelValuesService(values, service)
	}

	for _, k := range r.extraMetadataLabels {
		values = append(values, service.Metadata[k])
	}

	return values
}

func (r *surveyMetricsReporter) createSurveyInfo(service *svc.Attrs) {
	targetInfoLabelValues := r.labelValues(service)
	r.surveyInfo.WithLabelValues(targetInfoLabelValues...).Set(1)
}

func (r *surveyMetricsReporter) origService(uid svc.UID, service *svc.Attrs) *svc.Attrs {
	orig := service
	if origAttrs, ok := r.serviceMap[uid]; ok {
		orig = &origAttrs
	}
	return orig
}

func (r *surveyMetricsReporter) deleteSurveyInfo(uid svc.UID, service *svc.Attrs) {
	targetInfoLabelValues := r.labelValues(r.origService(uid, service))
	r.surveyInfo.DeleteLabelValues(targetInfoLabelValues...)
}

func (r *surveyMetricsReporter) setupPIDToServiceRelationship(pid int32, uid svc.UID) {
	r.pidsTracker.AddPID(pid, uid)
}

func (r *surveyMetricsReporter) disassociatePIDFromService(pid int32) (bool, svc.UID) {
	return r.pidsTracker.RemovePID(pid)
}

func (r *surveyMetricsReporter) handleProcessEvent(pe exec.ProcessEvent, log *slog.Logger) {
	log.Debug("Received new process event", "event type", pe.Type, "pid", pe.File.Pid, "attrs", pe.File.Service.UID)

	uid := pe.File.Service.UID

	switch pe.Type {
	case exec.ProcessEventTerminated:
		if deleted, origUID := r.disassociatePIDFromService(pe.File.Pid); deleted {
			log.Debug("deleting infos for", "pid", pe.File.Pid, "attrs", pe.File.Service.UID)
			r.deleteEventMetrics(origUID, &pe.File.Service)
			delete(r.serviceMap, origUID)
		}
	case exec.ProcessEventCreated:
		// Handle the case when the PID changed its feathers, e.g. got new metadata impacting the service name.
		// There's no new PID, just an update to the metadata.
		if staleUID, exists := r.pidsTracker.TracksPID(pe.File.Pid); exists && !staleUID.Equals(&uid) {
			log.Debug("updating older service definition", "from", staleUID, "new", uid)
			r.pidsTracker.ReplaceUID(staleUID, uid)
			if origAttrs, ok := r.serviceMap[staleUID]; ok {
				log.Debug("updating service attributes for", "service", uid)
				r.deleteEventMetrics(staleUID, &origAttrs)
				delete(r.serviceMap, staleUID)
				r.serviceMap[uid] = pe.File.Service
				r.createEventMetrics(&pe.File.Service)
				// we don't setup the pid again, we just replaced the metrics it's associated with
			}
			return
		}

		// Handle the case when we have new labels for same service
		// It could be a brand new PID with this information, so we fall through after deleting
		// the old target info
		if origAttrs, ok := r.serviceMap[uid]; ok {
			log.Debug("updating stale attributes for", "service", uid)
			r.deleteEventMetrics(uid, &origAttrs)
		}

		r.createEventMetrics(&pe.File.Service)
		r.serviceMap[uid] = pe.File.Service
		r.setupPIDToServiceRelationship(pe.File.Pid, uid)
	}
}

func (r *surveyMetricsReporter) watchForProcessEvents(ctx context.Context) {
	log := pslog()

	for {
		select {
		case <-ctx.Done():
			return
		case pe, ok := <-r.processEvents:
			if !ok {
				return
			}
			r.handleProcessEvent(pe, log)
		}
	}
}

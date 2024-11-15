package instrument

import (
	"runtime"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/beyla/pkg/buildinfo"
	"github.com/grafana/beyla/pkg/internal/connector"
)

// InternalMetrics accounts diverse events of the Beyla Cache service
type InternalMetrics interface {
	InformerNew()
	InformerUpdate()
	InformerDelete()

	ClientConnect()
	ClientDisconnect()

	MessageSubmit()
	MessageSucceed()
	MessageTimeout()
	MessageError()
}

type noopMetrics struct{}

func (n noopMetrics) InformerNew()      {}
func (n noopMetrics) InformerUpdate()   {}
func (n noopMetrics) InformerDelete()   {}
func (n noopMetrics) ClientConnect()    {}
func (n noopMetrics) ClientDisconnect() {}
func (n noopMetrics) MessageSubmit()    {}
func (n noopMetrics) MessageSucceed()   {}
func (n noopMetrics) MessageTimeout()   {}
func (n noopMetrics) MessageError()     {}

type promInternalMetrics struct {
	connector        *connector.PrometheusManager
	informerNew      prometheus.Counter
	informerUpdate   prometheus.Counter
	informerDelete   prometheus.Counter
	connectedClients prometheus.Gauge
	messageSubmit    prometheus.Counter
	messageSucceed   prometheus.Counter
	messageError     prometheus.Counter
	messageTimeout   prometheus.Counter
	beylaCacheInfo   prometheus.Gauge
}

func prometheusInternalMetrics(
	cfg *InternalMetricsConfig,
	manager *connector.PrometheusManager,
) *promInternalMetrics {
	pr := &promInternalMetrics{
		connector: manager,
		informerNew: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "beyla_kube_cache_informer_new",
			Help: "How many 'new' metadata events has the informer received",
		}),
		informerUpdate: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "beyla_kube_cache_informer_update",
			Help: "How many 'update' metadata events has the informer received",
		}),
		informerDelete: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "beyla_kube_cache_informer_delete",
			Help: "How many 'delete' metadata events has the informer received",
		}),
		connectedClients: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "beyla_kube_cache_connected_clients",
			Help: "How many concurrent Beyla instances are connected to this cache service",
		}),
		messageSubmit: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "beyla_kube_cache_client_message_submits",
			Help: "How many notifications have been started to be submitted to" +
				" the subscriber client. This includes messages not yet received or failed",
		}),
		messageSucceed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "beyla_kube_cache_client_message_successes",
			Help: "How many notifications have been successfully submitted to the subscriber client",
		}),
		messageError: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "beyla_kube_cache_client_message_errors",
			Help: "How many notifications couldn't be submitted to the subscriber client due to an error",
		}),
		messageTimeout: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "beyla_kube_cache_client_message_timeouts",
			Help: "How many notifications timed out before finish its submission to the subscriber client",
		}),
		beylaCacheInfo: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "beyla_kube_cache_internal_build_info",
			Help: "A metric with a constant '1' value labeled by version, revision, branch, " +
				"goversion from which Beyla was built, the goos and goarch for the build.",
			ConstLabels: map[string]string{
				"goarch":    runtime.GOARCH,
				"goos":      runtime.GOOS,
				"goversion": runtime.Version(),
				"version":   buildinfo.Version,
				"revision":  buildinfo.Revision,
			},
		}),
	}
	pr.beylaCacheInfo.Set(1)
	manager.Register(cfg.Port, cfg.Path,
		pr.informerNew,
		pr.informerUpdate,
		pr.informerDelete,
		pr.connectedClients,
		pr.messageSubmit,
		pr.messageSucceed,
		pr.messageError,
		pr.messageTimeout,
		pr.beylaCacheInfo)

	return pr
}

func (n *promInternalMetrics) InformerNew() {
	n.informerNew.Inc()
}
func (n *promInternalMetrics) InformerUpdate() {
	n.informerUpdate.Inc()
}
func (n *promInternalMetrics) InformerDelete() {
	n.informerDelete.Inc()
}
func (n *promInternalMetrics) ClientConnect() {
	n.connectedClients.Inc()
}
func (n *promInternalMetrics) ClientDisconnect() {
	n.connectedClients.Dec()
}
func (n *promInternalMetrics) MessageSubmit() {
	n.messageSubmit.Inc()
}
func (n *promInternalMetrics) MessageSucceed() {
	n.messageSucceed.Inc()
}
func (n *promInternalMetrics) MessageTimeout() {
	n.messageTimeout.Inc()
}
func (n *promInternalMetrics) MessageError() {
	n.messageError.Inc()
}

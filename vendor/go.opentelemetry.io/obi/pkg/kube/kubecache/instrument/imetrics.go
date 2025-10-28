// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package instrument

import (
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"go.opentelemetry.io/obi/pkg/buildinfo"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/connector"
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

	ForwardLag(seconds float64)
}

type noopMetrics struct{}

func (n noopMetrics) InformerNew()       {}
func (n noopMetrics) InformerUpdate()    {}
func (n noopMetrics) InformerDelete()    {}
func (n noopMetrics) ClientConnect()     {}
func (n noopMetrics) ClientDisconnect()  {}
func (n noopMetrics) MessageSubmit()     {}
func (n noopMetrics) MessageSucceed()    {}
func (n noopMetrics) MessageTimeout()    {}
func (n noopMetrics) MessageError()      {}
func (n noopMetrics) ForwardLag(float64) {}

type promInternalMetrics struct {
	connector        *connector.PrometheusManager
	informerEvents   *prometheus.CounterVec
	connectedClients prometheus.Gauge
	clientMessages   *prometheus.CounterVec
	beylaCacheInfo   prometheus.Gauge
	informerLag      prometheus.Histogram
}

func prometheusInternalMetrics(
	cfg *InternalMetricsConfig,
	manager *connector.PrometheusManager,
) *promInternalMetrics {
	pr := &promInternalMetrics{
		connector: manager,
		informerEvents: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attr.VendorPrefix + "_kube_cache_informer_events_total",
			Help: "How many metadata events has the informer received",
		}, []string{"type"}),
		connectedClients: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: attr.VendorPrefix + "_kube_cache_connected_clients",
			Help: "How many concurrent Beyla instances are connected to this cache service",
		}),
		clientMessages: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attr.VendorPrefix + "_kube_cache_client_messages_total",
			Help: "How many notifications have been started to be submitted to" +
				" the subscriber client",
		}, []string{"status"}),
		beylaCacheInfo: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: attr.VendorPrefix + "_kube_cache_internal_build_info",
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
		informerLag: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: attr.VendorPrefix + "_informer_receive_lag_seconds",
			Help: "How long, in seconds, it takes since a Kubernetes event happens until it received by this OBI instance",
			// Since K8s stores the timestamps with second precision, we initially provide buckets larger than 0.5s
			Buckets:                         []float64{0.5, 1, 2, 4, 8, 16, 32, 64, 128, 256},
			NativeHistogramBucketFactor:     2,
			NativeHistogramMaxExemplars:     20,
			NativeHistogramMinResetDuration: 10 * time.Minute,
		}),
	}
	pr.beylaCacheInfo.Set(1)
	manager.Register(cfg.Port, cfg.Path,
		pr.informerEvents,
		pr.connectedClients,
		pr.clientMessages,
		pr.beylaCacheInfo,
		pr.informerLag)

	return pr
}

func (n *promInternalMetrics) ForwardLag(seconds float64) {
	n.informerLag.Observe(seconds)
}

func (n *promInternalMetrics) InformerNew() {
	n.informerEvents.WithLabelValues("new").Inc()
}

func (n *promInternalMetrics) InformerUpdate() {
	n.informerEvents.WithLabelValues("update").Inc()
}

func (n *promInternalMetrics) InformerDelete() {
	n.informerEvents.WithLabelValues("delete").Inc()
}

func (n *promInternalMetrics) ClientConnect() {
	n.connectedClients.Inc()
}

func (n *promInternalMetrics) ClientDisconnect() {
	n.connectedClients.Dec()
}

func (n *promInternalMetrics) MessageSubmit() {
	n.clientMessages.WithLabelValues("submit").Inc()
}

func (n *promInternalMetrics) MessageSucceed() {
	n.clientMessages.WithLabelValues("success").Inc()
}

func (n *promInternalMetrics) MessageTimeout() {
	n.clientMessages.WithLabelValues("timeout").Inc()
}

func (n *promInternalMetrics) MessageError() {
	n.clientMessages.WithLabelValues("error").Inc()
}

func (n *promInternalMetrics) InformerLag(seconds float64) {
	n.informerLag.Observe(seconds)
}

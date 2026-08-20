package beyla

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

// TestOverrideOBIGlobalConfig_MetricNames pins the Beyla-renamed metric definitions. The
// Unit and Type must stay in sync with their OBI counterparts in
// vendor/go.opentelemetry.io/obi/pkg/export/attributes/metric.go: the OTEL exporters declare
// the unit on the instrument (so the weaver semconv registry validates against it) and both
// unit and type feed the derived Prometheus name. Failing here on an OBI bump is much
// cheaper than failing in a 30-minute integration run.
func TestOverrideOBIGlobalConfig_MetricNames(t *testing.T) {
	OverrideOBIGlobalConfig()

	for _, tc := range []struct {
		name                      attributes.Name
		section, otel, unit, prom string
		instrument                attributes.Instrument
	}{
		{attributes.NetworkFlow, "beyla.network.flow", "beyla.network.flow.bytes", "{bytes}",
			"beyla_network_flow_bytes_total", attributes.InstrumentCounter},
		{attributes.NetworkFlowPackets, "beyla.network.flow.packets", "beyla.network.flow.packets", "{packets}",
			"beyla_network_flow_packets_total", attributes.InstrumentCounter},
		{attributes.NetworkInterZone, "beyla.network.inter.zone", "beyla.network.inter.zone.bytes", "{bytes}",
			"beyla_network_inter_zone_bytes_total", attributes.InstrumentCounter},
		{attributes.StatTCPRtt, "beyla.stat.tcp.rtt", "beyla.stat.tcp.rtt", "s",
			"beyla_stat_tcp_rtt_seconds", attributes.InstrumentHistogram},
		{attributes.StatTCPFailedConnections, "beyla.stat.tcp.failed.connections", "beyla.stat.tcp.failed.connections", "",
			"beyla_stat_tcp_failed_connections_total", attributes.InstrumentCounter},
		{attributes.StatTCPRetransmits, "beyla.stat.tcp.retransmits", "beyla.stat.tcp.retransmits", "",
			"beyla_stat_tcp_retransmits_total", attributes.InstrumentCounter},
		{attributes.StatTCPIo, "beyla.stat.tcp.io", "beyla.stat.tcp.io", "By",
			"beyla_stat_tcp_io_bytes_total", attributes.InstrumentCounter},
	} {
		t.Run(tc.otel, func(t *testing.T) {
			assert.Equal(t, attributes.Section(tc.section), tc.name.Section)
			assert.Equal(t, tc.otel, tc.name.OTEL)
			assert.Equal(t, tc.unit, tc.name.Unit)
			assert.Equal(t, tc.instrument, tc.name.Type)
			assert.Equal(t, tc.prom, tc.name.Prom)
		})
	}
}

func TestGrafanaEndpointOverride(t *testing.T) {
	// GIVEN a Grafana Cloud configuration
	config, err := LoadConfig(strings.NewReader(`
grafana:
  otlp:
    cloud_submit: ["metrics", "traces"]
    cloud_zone: "eu-west-23"
    cloud_instance_id: "12345"
    cloud_api_key: "affafafaafkd"
`))
	require.NoError(t, err)
	obiCfg := config.AsOBI().OTELMetrics

	// WHEN OBI is requested to get the endpoint
	ep, _ := obiCfg.OTLPMetricsEndpoint()

	// THEN it returns the Grafana Cloud endpoint taken from the configuration
	assert.Equal(t, "https://otlp-gateway-eu-west-23.grafana.net/otlp", ep)
}

func TestGrafanaHeadersOverride_Metrics(t *testing.T) {
	authHeader := ""
	metricServer := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		for _, v := range req.Header.Values("Authorization") {
			authHeader = v
		}
	}))

	// GIVEN a Grafana Cloud configuration overriding the OTEL metrics endpoint
	config, err := LoadConfig(strings.NewReader(fmt.Sprintf(`
otel_metrics_export:
  endpoint: "%s"
grafana:
  otlp:
    cloud_submit: ["metrics"]
    cloud_zone: "eu-west-23"
    cloud_instance_id: "12345"
    cloud_api_key: "affafafaafkd"
`, metricServer.URL)))
	require.NoError(t, err)

	instancer := &otelcfg.MetricsExporterInstancer{Cfg: &config.AsOBI().OTELMetrics}

	// WHEN the metrics exporter starts to send metrics
	export, err := instancer.Instantiate(t.Context())
	require.NoError(t, err)
	_ = export.Export(t.Context(), &metricdata.ResourceMetrics{})

	// THEN it sends the metrics to the provided endpoint, with the Grafana Cloud authentication headers
	// Basic + output of: echo -n 12345:affafafaafkd | gbase64 -w 0
	assert.Equal(t, "Basic MTIzNDU6YWZmYWZhZmFhZmtk", authHeader)
}

func TestGrafanaHeadersOverride_Traces(t *testing.T) {
	authHeader := atomic.Pointer[string]{}
	empty := ""
	authHeader.Store(&empty)
	traceServer := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		for _, v := range req.Header.Values("Authorization") {
			authHeader.Store(&v)
		}
	}))

	// GIVEN a Grafana Cloud configuration overriding the OTEL traces endpoint
	config, err := LoadConfig(strings.NewReader(fmt.Sprintf(`
otel_traces_export:
  endpoint: "%s"
  batch_timeout: "10ms"
grafana:
  otlp:
    cloud_submit: ["traces"]
    cloud_zone: "eu-west-23"
    cloud_instance_id: "12345"
    cloud_api_key: "affafafaafkd"
`, traceServer.URL)))
	require.NoError(t, err)

	// WHEN the traces exporter starts sending traces
	queue := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(1))
	tr, err := otel.TracesReceiver(
		&global.ContextInfo{}, config.AsOBI().Traces, false,
		&attributes.SelectorConfig{}, queue)(t.Context())
	require.NoError(t, err)
	go tr(t.Context())
	queue.Send([]request.Span{{Type: request.EventTypeHTTP, Method: "/fooors",
		Start: time.Now().UnixNano() - 1000,
		End:   time.Now().UnixNano(),
	}})

	// THEN it sends the traces to the provided endpoint, with the Grafana Cloud authentication headers
	require.EventuallyWithT(t, func(t *assert.CollectT) {
		// Basic + output of: echo -n 12345:affafafaafkd | gbase64 -w 0
		assert.Equal(t, "Basic MTIzNDU6YWZmYWZhZmFhZmtk", *authHeader.Load())
	}, 3*time.Second, time.Millisecond)
}

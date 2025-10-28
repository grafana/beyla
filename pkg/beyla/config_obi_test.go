package beyla

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
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
	obiCfg := config.AsOBI().Metrics

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

	instancer := &otelcfg.MetricsExporterInstancer{Cfg: &config.AsOBI().Metrics}

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
	test.Eventually(t, 3*time.Second, func(t require.TestingT) {
		// Basic + output of: echo -n 12345:affafafaafkd | gbase64 -w 0
		assert.Equal(t, "Basic MTIzNDU6YWZmYWZhZmFhZmtk", *authHeader.Load())
	})
}

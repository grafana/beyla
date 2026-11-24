package components

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/kube/kubecache"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/transform"

	"github.com/grafana/beyla/v3/pkg/beyla"
	"github.com/grafana/beyla/v3/pkg/export/otel/bexport"
)

func TestKubernetesMetadataConfigPreservesMetadataCacheTLS(t *testing.T) {
	want := kubecache.ClientTLSConfig{
		CAFile:     "/tls/ca.crt",
		CertFile:   "/tls/client.crt",
		KeyFile:    "/tls/client.key",
		ServerName: "k8s-cache",
	}
	obiConfig := &obi.Config{}
	obiConfig.Attributes.Kubernetes.MetaCacheTLS = want
	config := beyla.FromOBI(obiConfig)
	require.Equal(t, want, config.Attributes.Kubernetes.MetaCacheTLS)

	metadataConfig := kubernetesMetadataConfig(config, nil, nil)
	require.Equal(t, want, metadataConfig.MetaCacheTLS)

	plainTextConfig := kubernetesMetadataConfig(&beyla.Config{}, nil, nil)
	require.Equal(t, kubecache.ClientTLSConfig{}, plainTextConfig.MetaCacheTLS)
}

func TestRunBeylaGPUWithoutDiscovery(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	require.NoError(t, listener.Close())

	cfg := beyla.DefaultConfig()
	cfg.Metrics.Features = bexport.FeatureGPU
	cfg.Prometheus.Port = port
	cfg.Prometheus.Path = "/metrics"
	cfg.Attributes.InstanceID.OverrideHostname = "gpu-node.example.com"
	cfg.Attributes.MetadataRetry.Timeout = 100 * time.Millisecond
	cfg.Attributes.Kubernetes.Enable = "false"
	cfg.NameResolver = nil
	cfg.ShutdownTimeout = time.Second
	require.False(t, cfg.Enabled(beyla.FeatureAppO11y))
	require.NoError(t, cfg.Validate())

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- RunBeyla(ctx, cfg) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			assert.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Error("Beyla did not stop after cancellation")
		}
	})

	client := &http.Client{Timeout: time.Second}
	url := fmt.Sprintf("http://127.0.0.1:%d/metrics", port)
	require.Eventually(t, func() bool {
		resp, err := client.Get(url)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		_, err = io.Copy(io.Discard, resp.Body)
		return err == nil && resp.StatusCode == http.StatusOK
	}, 10*time.Second, 20*time.Millisecond, "GPU-only startup should serve Prometheus without application discovery")
}

func TestServiceNameTemplate(t *testing.T) {

	cfg := &beyla.Config{
		Attributes: beyla.Attributes{
			Kubernetes: transform.KubernetesDecorator{
				ServiceNameTemplate: "{{asdf}}",
			},
		},
	}

	temp, err := buildServiceNameTemplate(cfg)

	assert.Nil(t, temp)
	if assert.Error(t, err) {
		assert.Equal(t, `unable to parse service name template: template: serviceNameTemplate:1: function "asdf" not defined`, err.Error())
	}

	cfg.Attributes.Kubernetes.ServiceNameTemplate = `{{- if eq .Meta.Pod nil }}{{.Meta.Name}}{{ else }}{{- .Meta.Namespace }}/{{ index .Meta.Labels "app.kubernetes.io/name" }}/{{ index .Meta.Labels "app.kubernetes.io/component" -}}{{ if .ContainerName }}/{{ .ContainerName -}}{{ end -}}{{ end -}}`
	temp, err = buildServiceNameTemplate(cfg)

	assert.NoError(t, err)
	assert.NotNil(t, temp)

	cfg.Attributes.Kubernetes.ServiceNameTemplate = ""
	temp, err = buildServiceNameTemplate(cfg)

	assert.Nil(t, temp)
	assert.Nil(t, err)
}

// See: https://github.com/grafana/beyla/issues/2410
func TestGrafanaCloudEndpointInContextInfo(t *testing.T) {
	// GIVEN a Beyla configuration with only Grafana Cloud settings (no explicit OTEL endpoint)
	config, err := beyla.LoadConfig(strings.NewReader(`
grafana:
  otlp:
    cloud_submit: ["metrics", "traces"]
    cloud_zone: "prod-gb-south-0"
    cloud_instance_id: "1234567"
    cloud_api_key: "REDACTED"
`))
	require.NoError(t, err)

	// Verify the Grafana config was loaded correctly
	assert.Equal(t, "prod-gb-south-0", config.Grafana.OTLP.CloudZone)
	assert.True(t, config.Grafana.OTLP.MetricsEnabled(), "Grafana metrics should be enabled")

	// WHEN buildCommonContextInfo creates the context info
	ctx := context.Background()
	ctxInfo, err := buildCommonContextInfo(ctx, config)
	require.NoError(t, err)

	// THEN the OTELMetricsExporter should resolve the endpoint from Grafana Cloud settings
	endpoint, isCommon := ctxInfo.OTELMetricsExporter.Cfg.OTLPMetricsEndpoint()

	// The endpoint should be the Grafana Cloud OTLP gateway URL
	expectedEndpoint := "https://otlp-gateway-prod-gb-south-0.grafana.net/otlp"
	assert.Equal(t, expectedEndpoint, endpoint,
		"OTELMetricsExporter should use Grafana Cloud endpoint when no explicit endpoint is set")
	assert.True(t, isCommon,
		"Endpoint should be marked as common (used for both metrics and traces)")
}

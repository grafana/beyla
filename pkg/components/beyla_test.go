package components

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/transform"

	"github.com/grafana/beyla/v3/pkg/beyla"
)

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

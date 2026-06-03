package components

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"

	"go.opentelemetry.io/obi/pkg/appolly/meta"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
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

func TestHasCloudProvider(t *testing.T) {
	t.Run("empty metadata returns false", func(t *testing.T) {
		nm := meta.NodeMeta{}
		assert.False(t, hasCloudProvider(nm))
	})

	t.Run("cloud.provider present returns true", func(t *testing.T) {
		nm := meta.NodeMeta{
			Metadata: []meta.Entry{
				{Key: attr.Name(semconv.CloudProviderKey), Value: "aws"},
			},
		}
		assert.True(t, hasCloudProvider(nm))
	})

	t.Run("other metadata without cloud.provider returns false", func(t *testing.T) {
		nm := meta.NodeMeta{
			Metadata: []meta.Entry{
				{Key: attr.Name("cloud.region"), Value: "us-east-1"},
				{Key: attr.Name("host.name"), Value: "web-01"},
			},
		}
		assert.False(t, hasCloudProvider(nm))
	})
}

func TestApplyHostIDFallback(t *testing.T) {
	t.Run("adds grafana.host.id when no k8s and no cloud", func(t *testing.T) {
		nm := meta.NodeMeta{}
		applyHostIDFallback(&nm, false)

		require.Len(t, nm.Metadata, 1)
		assert.Equal(t, attr.Name(grafanaHostIDAttr), nm.Metadata[0].Key)
		assert.NotEmpty(t, nm.Metadata[0].Value)
	})

	t.Run("skips when kubernetes is enabled", func(t *testing.T) {
		nm := meta.NodeMeta{}
		applyHostIDFallback(&nm, true)

		assert.Empty(t, nm.Metadata)
	})

	t.Run("skips when cloud provider is present", func(t *testing.T) {
		nm := meta.NodeMeta{
			Metadata: []meta.Entry{
				{Key: attr.Name(semconv.CloudProviderKey), Value: "gcp"},
			},
		}
		applyHostIDFallback(&nm, false)

		require.Len(t, nm.Metadata, 1)
		assert.Equal(t, attr.Name(semconv.CloudProviderKey), nm.Metadata[0].Key)
		assert.Equal(t, "gcp", nm.Metadata[0].Value)
	})
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

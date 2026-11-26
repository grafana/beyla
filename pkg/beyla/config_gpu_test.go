package beyla

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGPUMetricsWithoutDiscovery(t *testing.T) {
	for _, tc := range []struct {
		name    string
		yaml    string
		enabled bool
	}{
		{name: "Prometheus", yaml: "prometheus_export:\n  port: 9400\n", enabled: true},
		{name: "OTLP", yaml: "otel_metrics_export:\n  endpoint: http://localhost:4318\n", enabled: true},
		{name: "Grafana", yaml: `
grafana:
  otlp:
    cloud_submit: [metrics]
    cloud_zone: prod-gb-south-0
    cloud_instance_id: "123"
    cloud_api_key: test
`, enabled: true},
		{name: "no exporter"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := loadConfigFile(strings.NewReader("metrics:\n  features: [gpu]\n"+tc.yaml), map[string]string{}, nil)
			require.NoError(t, err)
			assert.False(t, cfg.Enabled(FeatureAppO11y))
			assert.Equal(t, tc.enabled, cfg.GPUMetricsEnabled())
			if tc.enabled {
				assert.NoError(t, cfg.Validate())
			} else {
				assert.Error(t, cfg.Validate())
			}
		})
	}
}

func TestGPUMetricsWithNetwork(t *testing.T) {
	cfg, err := loadConfigFile(strings.NewReader(`
metrics:
  features: [gpu, network]
prometheus_export:
  port: 9400
`), map[string]string{}, nil)
	require.NoError(t, err)
	assert.True(t, cfg.Enabled(FeatureNetO11y))
	assert.True(t, cfg.GPUMetricsEnabled())
	assert.False(t, cfg.Enabled(FeatureAppO11y))
	assert.NoError(t, cfg.Validate())
}

func TestGPUMetricsDisabledWithoutFeature(t *testing.T) {
	cfg, err := loadConfigFile(strings.NewReader("prometheus_export:\n  port: 9400\n"), map[string]string{}, nil)
	require.NoError(t, err)
	assert.False(t, cfg.GPUMetricsEnabled())
	assert.Error(t, cfg.Validate())
}

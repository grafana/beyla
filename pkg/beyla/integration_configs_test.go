package beyla

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadIntegrationFixture(t *testing.T, name string) *Config {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "internal", "test", "beyla_extensions", "configs", name))
	require.NoError(t, err)
	cfg, err := LoadConfig(bytes.NewReader(data))
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
	return cfg
}

func TestJavaHTTPClientIntegrationConfig(t *testing.T) {
	for _, mode := range []string{"headers", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("JAVA_HTTPCLIENT_PROPAGATION", mode)
			t.Setenv("JAVA_HTTPCLIENT_PORTS", "8080,8086")
			cfg := loadIntegrationFixture(t, "obi-config-java-httpclient-traceparent.yml")
			require.True(t, cfg.InstrumentationEnabled())
			require.Len(t, cfg.Discovery.Instrument, 1)
			assert.True(t, cfg.Discovery.Instrument[0].OpenPorts.Matches(8080))
			assert.True(t, cfg.Discovery.Instrument[0].OpenPorts.Matches(8086))
			assert.Equal(t, mode == "headers", cfg.EBPF.ContextPropagation.HasHeaders())
			assert.Equal(t, "http://127.0.0.1:4317", cfg.Traces.TracesEndpoint)
		})
	}

	t.Run("async source only", func(t *testing.T) {
		t.Setenv("JAVA_HTTPCLIENT_PORTS", "8080")
		cfg := loadIntegrationFixture(t, "obi-config-java-httpclient-traceparent.yml")
		require.Len(t, cfg.Discovery.Instrument, 1)
		assert.True(t, cfg.Discovery.Instrument[0].OpenPorts.Matches(8080))
		assert.False(t, cfg.Discovery.Instrument[0].OpenPorts.Matches(8086))
	})
}

func TestRoute53IntegrationConfig(t *testing.T) {
	t.Setenv("ROUTE53_HOSTED_ZONE_ID", "")
	cfg := loadIntegrationFixture(t, "obi-config-route53.yml")
	assert.Empty(t, cfg.CloudMetadata.Route53.HostedZoneIDs,
		"the fixture discovers the hosted zones associated with the mock VPC")
	assert.NoError(t, cfg.CloudMetadata.Route53.Validate())
}

func TestCohereIntegrationConfig(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "internal", "test", "beyla_extensions",
		"oats", "ai", "configs", "instrumenter-config-traces-genai-v2.yml"))
	require.NoError(t, err)
	cfg, err := LoadConfig(bytes.NewReader(data))
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
	assert.True(t, cfg.InstrumentationEnabled())
	assert.True(t, cfg.EBPF.PayloadExtraction.HTTP.GenAI.Cohere.Enabled)
	assert.True(t, cfg.Traces.Enabled())
	assert.True(t, cfg.OTELMetrics.EndpointEnabled())
	assert.Equal(t, uint32(65536), cfg.EBPF.BufferSizes.HTTP)
}

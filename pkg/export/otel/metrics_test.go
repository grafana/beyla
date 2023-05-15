package otel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetricsEndpoint(t *testing.T) {
	mcfg := MetricsConfig{
		ServiceName:     "svc-name",
		Endpoint:        "https://localhost:3131",
		MetricsEndpoint: "https://localhost:3232",
	}

	t.Run("testing with two endpoints", func(t *testing.T) {
		testMetricsEndpLen(t, 1, &mcfg)
	})

	mcfg = MetricsConfig{
		ServiceName:     "svc-name",
		Endpoint:        "https://localhost:3131",
		MetricsEndpoint: "https://localhost:3232",
	}

	t.Run("testing with only metrics endpoint", func(t *testing.T) {
		testMetricsEndpLen(t, 1, &mcfg)
	})

	mcfg.Endpoint = "https://localhost:3131"
	mcfg.MetricsEndpoint = ""

	t.Run("testing with only non-signal endpoint", func(t *testing.T) {
		testMetricsEndpLen(t, 1, &mcfg)
	})

	mcfg.Endpoint = "http://localhost:3131"
	t.Run("testing with insecure endpoint", func(t *testing.T) {
		testMetricsEndpLen(t, 2, &mcfg)
	})

	mcfg.Endpoint = "http://localhost:3131/path_to_endpoint"
	t.Run("testing with insecure endpoint and path", func(t *testing.T) {
		testMetricsEndpLen(t, 3, &mcfg)
	})

	mcfg.Endpoint = "http://localhost:3131/v1/metrics"
	t.Run("testing with insecure endpoint and containing v1/metrics", func(t *testing.T) {
		testMetricsEndpLen(t, 2, &mcfg)
	})
}

func testMetricsEndpLen(t *testing.T, expected int, mcfg *MetricsConfig) {
	opts, err := getMetricEndpointOptions(mcfg)
	require.NoError(t, err)
	// otlptracehttp.Options are notoriously hard to compare, so we just test the length
	assert.Equal(t, expected, len(opts))
}

func TestMissingSchemeInMetricsEndpoint(t *testing.T) {
	opts, err := getMetricEndpointOptions(&MetricsConfig{Endpoint: "http://foo:3030"})
	require.NoError(t, err)
	require.NotEmpty(t, opts)

	_, err = getMetricEndpointOptions(&MetricsConfig{Endpoint: "foo:3030"})
	require.Error(t, err)

	_, err = getMetricEndpointOptions(&MetricsConfig{Endpoint: "foo"})
	require.Error(t, err)
}

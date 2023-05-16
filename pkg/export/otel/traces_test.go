package otel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTracesEndpoint(t *testing.T) {
	tcfg := TracesConfig{
		ServiceName:        "svc-name",
		Endpoint:           "https://localhost:3131",
		TracesEndpoint:     "https://localhost:3232",
		MaxQueueSize:       4096,
		MaxExportBatchSize: 4096,
	}

	t.Run("testing with two endpoints", func(t *testing.T) {
		testTracesEndpLen(t, 1, &tcfg)
	})

	tcfg = TracesConfig{
		ServiceName:        "svc-name",
		TracesEndpoint:     "https://localhost:3232",
		MaxQueueSize:       4096,
		MaxExportBatchSize: 4096,
	}

	t.Run("testing with only trace endpoint", func(t *testing.T) {
		testTracesEndpLen(t, 1, &tcfg)
	})

	tcfg.Endpoint = "https://localhost:3131"
	tcfg.TracesEndpoint = ""

	t.Run("testing with only non-signal endpoint", func(t *testing.T) {
		testTracesEndpLen(t, 1, &tcfg)
	})

	tcfg.Endpoint = "http://localhost:3131"
	t.Run("testing with insecure endpoint", func(t *testing.T) {
		testTracesEndpLen(t, 2, &tcfg)
	})

	tcfg.Endpoint = "http://localhost:3131/path_to_endpoint"
	t.Run("testing with insecure endpoint and path", func(t *testing.T) {
		testTracesEndpLen(t, 3, &tcfg)
	})

	tcfg.Endpoint = "http://localhost:3131/v1/traces"
	t.Run("testing with insecure endpoint and containing v1/traces", func(t *testing.T) {
		testTracesEndpLen(t, 2, &tcfg)
	})
}

func testTracesEndpLen(t *testing.T, expected int, tcfg *TracesConfig) {
	opts, err := getTracesEndpointOptions(tcfg)
	require.NoError(t, err)
	// otlptracehttp.Options are notoriously hard to compare, so we just test the length
	assert.Equal(t, expected, len(opts))
}

func TestMissingSchemeInTracesEndpoint(t *testing.T) {
	opts, err := getTracesEndpointOptions(&TracesConfig{Endpoint: "http://foo:3030"})
	require.NoError(t, err)
	require.NotEmpty(t, opts)

	_, err = getTracesEndpointOptions(&TracesConfig{Endpoint: "foo:3030"})
	require.Error(t, err)

	_, err = getTracesEndpointOptions(&TracesConfig{Endpoint: "foo"})
	require.Error(t, err)
}

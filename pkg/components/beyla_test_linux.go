//go:build linux

package components

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v2/pkg/beyla"
)

// Tests fix for https://github.com/grafana/beyla/issues/926
func TestRunDontPanic(t *testing.T) {
	type testCase struct {
		description    string
		configProvider func() *beyla.Config
	}
	testCases := []testCase{{
		description: "otel endpoint but feature excluded",
		configProvider: func() *beyla.Config {
			cfg := beyla.DefaultConfig()
			cfg.Metrics.Features = []string{"application"}
			cfg.NetworkFlows.Enable = true
			cfg.Metrics.CommonEndpoint = "http://localhost"
			return cfg
		},
	}, {
		description: "prom endpoint but feature excluded",
		configProvider: func() *beyla.Config {
			cfg := beyla.DefaultConfig()
			cfg.Prometheus.Features = []string{"application"}
			cfg.NetworkFlows.Enable = true
			cfg.Prometheus.Port = 9090
			return cfg
		},
	}, {
		description: "otel endpoint, otel feature excluded, but prom enabled",
		configProvider: func() *beyla.Config {
			cfg := beyla.DefaultConfig()
			cfg.Metrics.Features = []string{"application"}
			cfg.NetworkFlows.Enable = true
			cfg.Metrics.CommonEndpoint = "http://localhost"
			cfg.Prometheus.Port = 9090
			return cfg
		},
	}, {
		description: "all endpoints, all features excluded",
		configProvider: func() *beyla.Config {
			cfg := beyla.DefaultConfig()
			cfg.NetworkFlows.Enable = true
			cfg.Prometheus.Port = 9090
			cfg.Prometheus.Features = []string{"application"}
			cfg.Metrics.CommonEndpoint = "http://localhost"
			cfg.Metrics.Features = []string{"application"}
			return cfg
		},
	}}
	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			cfg := tc.configProvider()
			require.NoError(t, cfg.Validate())

			require.NotPanics(t, func() {
				_ = RunBeyla(t.Context(), cfg)
			})
		})
	}
}

func TestNetworkEnabled(t *testing.T) {
	require.NoError(t, os.Setenv("BEYLA_NETWORK_METRICS", "true"))
	cfg, err := beyla.LoadConfig(bytes.NewReader(nil))
	assert.NoError(t, err)
	assert.True(t, cfg.Enabled(beyla.FeatureNetO11y))
}

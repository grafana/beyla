package beyla

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/cmd/obi/configbridge"
	"go.opentelemetry.io/obi/pkg/appolly/discover"
	obicfg "go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestV2FixturesRoundTrip(t *testing.T) {
	cases := []struct {
		name  string
		path  string
		check func(t *testing.T, cfg *Config)
	}{
		{
			name: "peer metadata",
			path: "../../.obi-src/internal/test/integration/configs/obi-config-peer-metadata-server-v2.yml",
			check: func(t *testing.T, cfg *Config) {
				require.True(t, cfg.PeerMetadata.Enabled)
				require.Equal(t, 8998, cfg.PeerMetadata.Port)
				require.Equal(t, time.Second, cfg.PeerMetadata.RefreshInterval)
				require.Equal(t, 6*time.Second, cfg.PeerMetadata.CallerTTL)
				require.Equal(t, 8999, cfg.Prometheus.Port)
				require.True(t, cfg.Discovery.Instrument[0].CmdArgs.MatchString("/opt/peer-metadata/app.py"))
			},
		},
		{
			name: "route53",
			path: "../../.obi-src/internal/test/integration/configs/obi-config-route53.yml",
			check: func(t *testing.T, cfg *Config) {
				require.Equal(t, time.Second, cfg.CloudMetadata.Route53.RefreshInterval)
				require.True(t, hasOpenPort(cfg, 8080))
				require.Equal(t, 8999, cfg.Prometheus.Port)
			},
		},
		{
			name: "config reload",
			path: "../../.obi-src/internal/test/integration/configs/obi-config-reload-v2.yml",
			check: func(t *testing.T, cfg *Config) {
				require.True(t, hasOpenPort(cfg, 18060))
				require.Equal(t, 2*time.Second, cfg.ShutdownTimeout)
			},
		},
		{
			name: "java traceparent",
			path: "../../.obi-src/internal/test/integration/configs/obi-config-java-httpclient-traceparent.yml",
			check: func(t *testing.T, cfg *Config) {
				require.Equal(t, obicfg.ContextPropagationHeaders, cfg.EBPF.ContextPropagation)
				require.True(t, hasOpenPort(cfg, 8080))
				require.True(t, hasOpenPort(cfg, 8086))
				require.True(t, cfg.V2ProtocolSelection().HTTPEnabled())
			},
		},
		{
			name: "cohere genai",
			path: "../../.obi-src/internal/test/oats/ai/configs/instrumenter-config-traces-genai-v2.yml",
			check: func(t *testing.T, cfg *Config) {
				require.True(t, cfg.EBPF.PayloadExtraction.HTTP.GenAI.Cohere.Enabled)
				require.True(t, hasOpenPort(cfg, 8080))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile(tc.path)
			require.NoError(t, err)
			obiCfg, err := configbridge.LoadV2(data)
			require.NoError(t, err)
			cfg := FromOBI(obiCfg)
			selection := instrumentations.NewInstrumentationSelection(obiCfg.OTELMetrics.Instrumentations)
			var updater *discover.CriteriaUpdater
			if obiCfg.Enabled(obi.FeatureAppO11y) {
				updater = discover.NewCriteriaUpdater(obiCfg)
			}
			cfg.SetV2Runtime(selection, updater)
			// The pipeline reads the converted config, so the round trip has to survive.
			round := cfg.AsOBI()
			require.Equal(t, obiCfg.PeerMetadata.Enabled, round.PeerMetadata.Enabled)
			require.Equal(t, obiCfg.CloudMetadata.Route53.RefreshInterval, round.CloudMetadata.Route53.RefreshInterval)
			require.Equal(t, obiCfg.EBPF.ContextPropagation, round.EBPF.ContextPropagation)
			require.NoError(t, cfg.Validate())
			require.NotNil(t, cfg.CriteriaUpdates())
			tc.check(t, cfg)
		})
	}
}

func TestV1DocumentIsNotV2(t *testing.T) {
	_, err := configbridge.LoadV2([]byte("discovery:\n  instrument:\n    - open_ports: \"8080\"\n"))
	require.Error(t, err)
	require.True(t, configbridge.IsNotV2(err))

	_, err = configbridge.LoadV2(nil)
	require.Error(t, err)
	require.True(t, configbridge.IsNotV2(err))
}

func hasOpenPort(cfg *Config, port int) bool {
	for i := range cfg.Discovery.Instrument {
		if cfg.Discovery.Instrument[i].OpenPorts.Matches(port) {
			return true
		}
	}
	return false
}

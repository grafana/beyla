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
		name string
		path string
		// env holds the variables the integration compose files export for the
		// fixture, so the ${...} substitutions resolve the same way here.
		env   map[string]string
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
		// The fixtures below used to carry a Beyla-only block of v1-equivalent
		// keys, appended by scripts/generate-obi-tests.sh back when
		// cmd/beyla/main.go could only load v1 documents. These cases assert
		// that the v2 loader now derives the same effective configuration on its
		// own, so the appended block stays gone: OBI's v2 document validator
		// rejects unknown top-level fields, and re-adding it would fail startup
		// for every suite using these fixtures.
		{
			name: "standalone v2 document",
			path: "../../.obi-src/internal/test/integration/configs/obi-config-v2.yml",
			check: func(t *testing.T, cfg *Config) {
				require.Equal(t, 8999, cfg.Prometheus.Port)
				require.Equal(t, "/metrics", cfg.Prometheus.Path)
				require.Equal(t, "http://jaeger:4317", cfg.Traces.TracesEndpoint)
				require.Equal(t, "http://otelcol:4317", cfg.OTELMetrics.MetricsEndpoint)
			},
		},
		{
			name: "log enricher",
			path: "../../.obi-src/internal/test/integration/configs/obi-config-log-enricher-v2.yml",
			env: map[string]string{
				"OTEL_EBPF_OPEN_PORT":       "8080",
				"OTEL_EBPF_EXECUTABLE_PATH": "testserver",
			},
			check: func(t *testing.T, cfg *Config) {
				// correlation.log_trace_annotation.match drives the enricher
				// selection; the integration suites substitute the port and the
				// executable name through the environment.
				require.Len(t, cfg.EBPF.LogEnricher.Services, 2)
				require.True(t, logEnricherMatchesPort(cfg, 8080))
			},
		},
		{
			name: "log enricher unselected",
			path: "../../.obi-src/internal/test/integration/configs/obi-config-log-enricher-unselected-v2.yml",
			env: map[string]string{
				"OTEL_EBPF_OPEN_PORT":       "8080",
				"OTEL_EBPF_EXECUTABLE_PATH": "testserver",
			},
			check: func(t *testing.T, cfg *Config) {
				// Deliberately matches nothing: no test server listens on port 1.
				require.Len(t, cfg.EBPF.LogEnricher.Services, 1)
				require.True(t, logEnricherMatchesPort(cfg, 1))
				require.False(t, logEnricherMatchesPort(cfg, 8080))
			},
		},
		{
			name: "multiexec connection info",
			path: "../../.obi-src/internal/test/integration/configs/obi-config-multiexec-connectioninfo.yml",
			check: func(t *testing.T, cfg *Config) {
				// otelcol:4017 is the gRPC receiver. The Beyla-only v1 block
				// this fixture used to carry pointed the otlp_grpc exporter at
				// 4018, which is the HTTP receiver.
				require.Equal(t, "http://otelcol:4017", cfg.OTELMetrics.MetricsEndpoint)
				require.True(t, cfg.Metrics.Features.ConnectionInfo())
				require.True(t, hasOpenPort(cfg, 8080))
				require.True(t, hasOpenPort(cfg, 8088))
				require.True(t, hasOpenPort(cfg, 7773))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
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

func logEnricherMatchesPort(cfg *Config, port int) bool {
	for _, sel := range cfg.EBPF.LogEnricher.Services {
		for i := range sel.Service {
			if sel.Service[i].OpenPorts.Matches(port) {
				return true
			}
		}
	}
	return false
}

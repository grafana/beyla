package beyla

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/obi"

	servicesextra "github.com/grafana/beyla/v3/pkg/services"
)

func TestSurveySocketAppsConfig(t *testing.T) {
	t.Run("disabled by default", func(t *testing.T) {
		cfg, err := LoadConfig(nil)
		require.NoError(t, err)
		assert.False(t, cfg.Discovery.Survey.SocketAppsEnabled())
	})
	t.Run("yaml", func(t *testing.T) {
		cfg, err := LoadConfig(strings.NewReader(`
discovery:
  survey:
    - exe_path: "*"
      socket_apps: true
      k8s_namespace: "prod-*"
      k8s_pod_labels:
        app: "worker-*"
    - exe_path: "/opt/batch/*"
    - exe_path: "/opt/tools/*"
      socket_apps: false
`))
		require.NoError(t, err)
		require.Len(t, cfg.Discovery.Survey, 3)
		assert.True(t, cfg.Discovery.Survey.SocketAppsEnabled())
		assert.True(t, cfg.Discovery.Survey[0].SocketApps)
		assert.False(t, cfg.Discovery.Survey[1].SocketApps)
		assert.False(t, cfg.Discovery.Survey[2].SocketApps)
		assert.True(t, cfg.Discovery.Survey[0].Path.MatchString("/app"))
		assert.True(t, cfg.Discovery.Survey[1].Path.MatchString("/opt/batch/job"))
		assert.NotContains(t, cfg.Discovery.Survey[0].Metadata, "socket_apps")
		require.Contains(t, cfg.Discovery.Survey[0].Metadata, "k8s_namespace")
		assert.True(t, cfg.Discovery.Survey[0].Metadata["k8s_namespace"].MatchString("prod-eu"))
		assert.True(t, cfg.Discovery.Survey[0].PodLabels["app"].MatchString("worker-1"))
		assert.True(t, cfg.Discovery.SurveyEnabled())
		assert.False(t, cfg.Discovery.AppDiscoveryEnabled())
		assert.Empty(t, cfg.AsOBI().Discovery.Instrument, "socket_apps must not enable instrumentation")
	})
	t.Run("ordinary survey does not enable watcher", func(t *testing.T) {
		cfg, err := LoadConfig(strings.NewReader(`
discovery:
  survey:
    - exe_path: "*"
    - exe_path: "/opt/batch/*"
      socket_apps: false
`))
		require.NoError(t, err)
		assert.True(t, cfg.Discovery.SurveyEnabled())
		assert.False(t, cfg.Discovery.Survey.SocketAppsEnabled())
	})
	t.Run("socket activity alone", func(t *testing.T) {
		cfg, err := LoadConfig(strings.NewReader(`
discovery:
  survey:
    - socket_apps: true
`))
		require.NoError(t, err)
		assert.True(t, cfg.Discovery.Survey.SocketAppsEnabled())
		assert.True(t, cfg.Discovery.SurveyEnabled())
		assert.Empty(t, cfg.AsOBI().Discovery.Instrument)
	})
	t.Run("OBI conversion", func(t *testing.T) {
		cfg := FromOBI(&obi.DefaultConfig)
		assert.Empty(t, cfg.Discovery.Survey)
		cfg.Discovery.Survey = servicesextra.SurveyDefinitionCriteria{{SocketApps: true}}
		assert.NotPanics(t, func() { cfg.AsOBI() })
	})
}

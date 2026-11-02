package beyla

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// refreshTestConfig exercises the settings that the loading and validation mutate: span metric
// formats resolved from "all", Grafana OTLP headers and survey default excludes.
func refreshTestConfig(selection string) []byte {
	return fmt.Appendf(nil, `
otel_metrics_export:
  endpoint: http://localhost:4318
prometheus_export:
  port: 9090
metrics:
  features: [all]
grafana:
  otlp:
    cloud_zone: prod-eu-west-0
    cloud_instance_id: "12345"
    cloud_api_key: synthetic-test-key
routes:
  unmatched: heuristic
discovery:
  survey:
    - exe_path: "*survey*"
%s`, selection)
}

const refreshTestSelection = `
  instrument:
    - open_ports: 8080
      name: frontend
`

func loadStartupConfig(t *testing.T, data []byte) *Config {
	t.Helper()
	cfg, err := LoadConfig(strings.NewReader(string(data)))
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
	return cfg
}

func TestLoadRefreshConfig_UnchangedFile(t *testing.T) {
	data := refreshTestConfig(refreshTestSelection)
	startup := loadStartupConfig(t, data)

	refreshed, err := LoadRefreshConfig(data, nil)
	require.NoError(t, err)

	assert.Empty(t, startup.ChangedSettings(refreshed))
	assert.Equal(t, startup.AsOBI().Metrics.Features, refreshed.AsOBI().Metrics.Features,
		"refresh validation must resolve span metric formats as the startup validation does")
}

func TestLoadRefreshConfig_SelectionChanges(t *testing.T) {
	startup := loadStartupConfig(t, refreshTestConfig(refreshTestSelection))

	for _, tc := range []struct {
		name      string
		selection string
	}{
		{name: "changed predicate", selection: `
  instrument:
    - open_ports: 9090
      name: frontend
`},
		{name: "added definition", selection: `
  instrument:
    - open_ports: 8080
      name: frontend
    - exe_path: "*backend*"
`},
		{name: "added exclusion", selection: `
  instrument:
    - open_ports: 8080
      name: frontend
  exclude_instrument:
    - exe_path: "*debug*"
`},
		{name: "all definitions removed", selection: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refreshed, err := LoadRefreshConfig(refreshTestConfig(tc.selection), nil)
			require.NoError(t, err)
			assert.Empty(t, startup.ChangedSettings(refreshed))
		})
	}
}

func TestLoadRefreshConfig_OtherChanges(t *testing.T) {
	startup := loadStartupConfig(t, refreshTestConfig(refreshTestSelection))

	for _, tc := range []struct {
		name    string
		config  string
		changed []string
	}{
		{name: "exporter endpoint", config: strings.Replace(string(refreshTestConfig(refreshTestSelection)),
			"http://localhost:4318", "http://collector:4318", 1),
			changed: []string{"otel_metrics_export.endpoint"}},
		{name: "survey criteria", config: strings.Replace(string(refreshTestConfig(refreshTestSelection)),
			"*survey*", "*other*", 1),
			changed: []string{"discovery.survey"}},
		{name: "routes", config: strings.Replace(string(refreshTestConfig(refreshTestSelection)),
			"heuristic", "wildcard", 1),
			changed: []string{"routes.unmatched"}},
		{name: "kubernetes resource labels", config: string(refreshTestConfig(refreshTestSelection)) + `
attributes:
  kubernetes:
    resource_labels:
      service.name: [app.kubernetes.io/name]
`, changed: []string{"attributes.kubernetes.resource_labels"}},
		{name: "beyla-only section", config: string(refreshTestConfig(refreshTestSelection)) + `
topology:
  spans: [inter_cluster]
`, changed: []string{"topology.spans"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refreshed, err := LoadRefreshConfig([]byte(tc.config), nil)
			require.NoError(t, err)
			assert.Equal(t, tc.changed, startup.ChangedSettings(refreshed))
		})
	}
}

func TestLoadRefreshConfig_Invalid(t *testing.T) {
	_, err := LoadRefreshConfig([]byte("discovery: [not a map"), nil)
	require.Error(t, err)

	_, err = LoadRefreshConfig(refreshTestConfig(refreshTestSelection+`
  instrument_all_local: true
`), nil)
	require.ErrorContains(t, err, "mutually exclusive")
}

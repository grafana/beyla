package beyla

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/kube/kubeflags"

	servicesextra "github.com/grafana/beyla/v3/pkg/services"
)

// TestInstrumentAllLocalConfig verifies activation, conversion, and independence from survey.
func TestInstrumentAllLocalConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		yaml string
		env  string
		want bool
	}{
		{name: "default"},
		{name: "yaml", yaml: "discovery:\n  instrument_all_local: true", want: true},
		{name: "environment", env: "true", want: true},
		{name: "environment overrides yaml", yaml: "discovery:\n  instrument_all_local: true", env: "false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("BEYLA_DISCOVERY_INSTRUMENT_ALL_LOCAL", tc.env)
			cfg, err := LoadConfig(strings.NewReader(tc.yaml))
			require.NoError(t, err)
			assert.Equal(t, tc.want, cfg.Discovery.InstrumentAllLocal)
			assert.Equal(t, tc.want, cfg.Enabled(FeatureAppO11y))
			assert.False(t, cfg.Discovery.SurveyEnabled())
			assert.False(t, cfg.Enabled(FeatureNetO11y))
			assert.False(t, cfg.Enabled(FeatureStatsO11y))
			assert.Empty(t, cfg.AsOBI().Discovery.Instrument)
			assert.False(t, FromOBI(cfg.AsOBI()).Discovery.InstrumentAllLocal)
			if tc.want {
				assert.Equal(t, servicesextra.DefaultExcludeInstrumentWithSurvey, cfg.Discovery.DefaultExcludeInstrument)
			}
		})
	}
}

// TestInstrumentAllLocalValidation verifies selector conflicts and supported combinations.
func TestInstrumentAllLocalValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		yaml string
		env  string
	}{
		{name: "instrument", yaml: "discovery:\n  instrument:\n    - exe_path: '*'"},
		{name: "services", yaml: "discovery:\n  services:\n    - exe_path: '.*'"},
		{name: "port", yaml: "open_port: 8080"},
		{name: "pid", yaml: "target_pids: [1234]"},
		{name: "legacy executable", yaml: "executable_name: '.*'"},
		{name: "executable", env: "BEYLA_AUTO_TARGET_EXE"},
		{name: "language", env: "BEYLA_AUTO_TARGET_LANGUAGE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.env != "" {
				t.Setenv(tc.env, "*")
			}
			cfg, err := LoadConfig(strings.NewReader(tc.yaml))
			require.NoError(t, err)
			cfg.Discovery.InstrumentAllLocal = true
			require.ErrorContains(t, cfg.Validate(), "instrument_all_local is mutually exclusive")
		})
	}

	cfg, err := LoadConfig(strings.NewReader(`
trace_printer: text
discovery:
  instrument_all_local: true
  survey:
    - exe_path: "*"
  exclude_instrument:
    - exe_path: "/opt/excluded/*"
`))
	require.NoError(t, err)
	cfg.Attributes.Kubernetes.Enable = kubeflags.EnabledTrue
	require.NoError(t, cfg.Validate(), "survey and Kubernetes do not conflict with local instrumentation")
	assert.True(t, cfg.Discovery.InstrumentAllLocal)
	assert.True(t, cfg.Discovery.SurveyEnabled())
	assert.True(t, cfg.AsOBI().Discovery.ExcludeInstrument[0].Path.MatchString("/opt/excluded/app"))
}

// TestInstrumentAllLocalCustomExclusions preserves explicitly configured default exclusions.
func TestInstrumentAllLocalCustomExclusions(t *testing.T) {
	cfg, err := LoadConfig(strings.NewReader(`
discovery:
  instrument_all_local: true
  default_exclude_instrument:
    - exe_path: "/opt/custom/*"
`))
	require.NoError(t, err)
	require.Len(t, cfg.Discovery.DefaultExcludeInstrument, 1)
	assert.True(t, cfg.Discovery.DefaultExcludeInstrument[0].Path.MatchString("/opt/custom/app"))
	assert.False(t, cfg.Discovery.DefaultExcludeInstrument[0].Path.MatchString("/usr/sbin/sshd"))
}

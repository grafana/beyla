package configrefresh

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/services"

	"github.com/grafana/beyla/v3/pkg/beyla"
)

func testConfig(selection string) []byte {
	return fmt.Appendf(nil, `
otel_traces_export:
  endpoint: http://localhost:4318
discovery:
%s`, selection)
}

func portSelection(port int) string {
	return fmt.Sprintf(`
  instrument:
    - open_ports: %d
      name: frontend
`, port)
}

func startupConfig(t *testing.T, data []byte) *beyla.Config {
	t.Helper()
	cfg, err := beyla.LoadConfig(bytes.NewReader(data))
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
	return cfg
}

// newAcceptingRefresher stands in for the OBI criteria matcher, accepting every update that
// passes the refresher and updater checks.
func newAcceptingRefresher(t *testing.T, data []byte) *Refresher {
	t.Helper()
	refresher, err := New(startupConfig(t, data), data)
	require.NoError(t, err)

	updates := refresher.Updater().Updates()
	go func() {
		for {
			select {
			case <-t.Context().Done():
				return
			case update := <-updates.Requests():
				updates.Complete(update, nil)
			}
		}
	}()
	return refresher
}

func TestRefresher_AcceptsSelectionChanges(t *testing.T) {
	initial := testConfig(portSelection(8080))

	for _, tc := range []struct {
		name   string
		config []byte
	}{
		{name: "unchanged", config: initial},
		{name: "changed predicate", config: testConfig(portSelection(9090))},
		{name: "added definition", config: testConfig(portSelection(8080) + `    - exe_path: "*backend*"
`)},
		{name: "added exclusion", config: testConfig(portSelection(8080) + `  exclude_instrument:
    - exe_path: "*debug*"
`)},
		{name: "all definitions removed", config: testConfig("")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refresher := newAcceptingRefresher(t, initial)
			require.NoError(t, refresher.Refresh(t.Context(), tc.config))
		})
	}
}

func TestRefresher_IgnoresEnvironmentSetByThePipeline(t *testing.T) {
	initial := testConfig(portSelection(8080))
	refresher := newAcceptingRefresher(t, initial)

	// The OTLP exporters set the protocol they guess for the endpoint once they start.
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "http/protobuf")
	reloaded, err := beyla.LoadRefreshConfig(initial, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"otel_traces_export.TracesProtocol"}, refresher.startup.ChangedSettings(reloaded),
		"loading from the current environment must see the variable")

	require.NoError(t, refresher.Refresh(t.Context(), testConfig(portSelection(9090))))
}

func TestRefresher_ExpandsTheYAMLWithTheStartupEnvironment(t *testing.T) {
	const protocolEnv = "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"
	withProtocol := func(port int) []byte {
		return bytes.Replace(testConfig(portSelection(port)), []byte("endpoint: http://localhost:4318"),
			[]byte("endpoint: http://localhost:4318\n  protocol: ${"+protocolEnv+"}"), 1)
	}
	t.Setenv(protocolEnv, "")
	require.NoError(t, os.Unsetenv(protocolEnv))

	initial := withProtocol(8080)
	refresher := newAcceptingRefresher(t, initial)

	// The OTLP exporters set the protocol they guess for the endpoint once they start.
	t.Setenv(protocolEnv, "http/protobuf")
	reloaded, err := beyla.LoadRefreshConfig(initial, nil)
	require.NoError(t, err)
	require.Contains(t, refresher.startup.ChangedSettings(reloaded), "otel_traces_export.protocol",
		"expanding the YAML with the current environment must see the variable")

	require.NoError(t, refresher.Refresh(t.Context(), withProtocol(9090)))
}

func TestRefresher_RejectsOtherChanges(t *testing.T) {
	initial := testConfig(portSelection(8080))

	for _, tc := range []struct {
		name   string
		config []byte
		error  string
	}{
		{
			name:   "exporter",
			config: bytes.Replace(initial, []byte("localhost:4318"), []byte("collector:4318"), 1),
			error:  "restart Beyla to apply changes to otel_traces_export.endpoint",
		},
		{
			name: "survey criteria",
			config: testConfig(portSelection(8080) + `  survey:
    - exe_path: "*survey*"
`),
			error: "restart Beyla to apply changes to discovery.survey",
		},
		{
			name:   "service settings of an existing predicate",
			config: bytes.Replace(initial, []byte("frontend"), []byte("backend"), 1),
			error:  "service settings changed",
		},
		{
			name:   "invalid YAML",
			config: []byte("discovery: [not a map"),
			error:  "parsing YAML configuration",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refresher := newAcceptingRefresher(t, initial)
			assert.ErrorContains(t, refresher.Refresh(t.Context(), tc.config), tc.error)
		})
	}
}

func TestRefresher_RejectsMalformedSamplerRatios(t *testing.T) {
	for _, selection := range []string{"instrument", "services"} {
		t.Run(selection, func(t *testing.T) {
			config := func(global, service string) []byte {
				return fmt.Appendf(nil, `
otel_traces_export:
  endpoint: http://localhost:4318
  sampler: {name: traceidratio, arg: %q}
discovery:
  %s:
    - open_ports: 8080
      sampler: {name: parentbased_traceidratio, arg: %q}
`, global, selection, service)
			}

			// Startup accepts a malformed ratio. A subsequent valid reload can correct it.
			r := newAcceptingRefresher(t, config("0,1", "0.25"))
			require.NoError(t, r.Refresh(t.Context(), config("0.1", "0.25")))
			updates := r.Updater().Updates()
			for _, tc := range []struct{ global, service, field string }{
				{"0,1", "0.5", "otel_traces_export.sampler"},
				{"0.5", "0,25", "discovery." + selection + "[0].sampler"},
				{"NaN", "0.5", "otel_traces_export.sampler"},
				{"+Inf", "0.5", "otel_traces_export.sampler"},
				{"", "0.5", "otel_traces_export.sampler"},
				{"-0.1", "0.5", "otel_traces_export.sampler"},
				{"1.1", "0.5", "otel_traces_export.sampler"},
			} {
				require.ErrorContains(t, r.Refresh(t.Context(), config(tc.global, tc.service)), tc.field)
				require.Equal(t, &services.SamplerConfig{Name: services.SamplerTraceIDRatio, Arg: "0.1"}, updates.Sampler())
				include, _ := updates.Current()
				require.Len(t, include, 1)
				require.Equal(t, &services.SamplerConfig{Name: services.SamplerParentBasedTraceIDRatio, Arg: "0.25"}, include[0].GetSamplerConfig())
			}
			require.NoError(t, r.Refresh(t.Context(), config("0", "1")))
		})
	}
}

func TestRefresher_InstrumentAllLocalSampling(t *testing.T) {
	initial := testConfig(`  instrument_all_local: true
  exclude_instrument:
    - exe_path: "*debug*"
`)
	cfg := startupConfig(t, initial)
	refresher, err := New(cfg, initial)
	require.NoError(t, err)
	require.Nil(t, refresher.Updater())
	require.NotNil(t, refresher.setSampler)
	require.Same(t, cfg.LocalPIDSelector(), cfg.LocalPIDSelector())
	var applied []services.SamplerConfig
	setSampler := refresher.setSampler
	refresher.setSampler = func(s services.SamplerConfig) {
		applied = append(applied, s)
		setSampler(s)
	}
	ratio := bytes.Replace(initial, []byte("  endpoint:"), []byte("  sampler: {name: traceidratio, arg: \"0.25\"}\n  endpoint:"), 1)
	require.NoError(t, refresher.Refresh(t.Context(), ratio))
	malformed := bytes.Replace(ratio, []byte("0.25"), []byte("0,25"), 1)
	require.ErrorContains(t, refresher.Refresh(t.Context(), malformed), "otel_traces_export.sampler")

	// A rejected mixed edit cannot reset the sampler to the startup default.
	editedExclusion := bytes.Replace(initial, []byte("*debug*"), []byte("*other*"), 1)
	require.ErrorContains(t, refresher.Refresh(t.Context(), editedExclusion), "discovery.exclude_instrument")

	newRatio := bytes.Replace(ratio, []byte("0.25"), []byte("0.75"), 1)
	require.NoError(t, refresher.Refresh(t.Context(), newRatio))
	require.NoError(t, refresher.Refresh(t.Context(), initial))
	require.Equal(t, []services.SamplerConfig{
		{Name: services.SamplerTraceIDRatio, Arg: "0.25"},
		{Name: services.SamplerTraceIDRatio, Arg: "0.75"},
		cfg.Traces.SamplerConfig,
	}, applied)
}

func TestNew_SurveyOnly(t *testing.T) {
	data := testConfig(`  survey:
    - exe_path: "*survey*"
`)
	_, err := New(startupConfig(t, data), data)
	require.ErrorContains(t, err, "not enabled at startup")
	assert.ErrorContains(t, err, "restart Beyla")
}

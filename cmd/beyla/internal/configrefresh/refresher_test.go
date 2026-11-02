package configrefresh

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
			error:  "only discovery selection criteria can be refreshed",
		},
		{
			name: "survey criteria",
			config: testConfig(portSelection(8080) + `  survey:
    - exe_path: "*survey*"
`),
			error: "only discovery selection criteria can be refreshed",
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

func TestNew_UnsupportedPipelines(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config []byte
		error  string
	}{
		{
			name: "instrument all local",
			config: testConfig(`  instrument_all_local: true
`),
			error: "instrument_all_local",
		},
		{
			name: "survey only",
			config: testConfig(`  survey:
    - exe_path: "*survey*"
`),
			error: "not enabled at startup",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(startupConfig(t, tc.config), tc.config)
			require.ErrorContains(t, err, tc.error)
			assert.ErrorContains(t, err, "restart Beyla")
		})
	}
}

package pipe

import (
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/cmd/obi/configbridge"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/obi"

	"github.com/grafana/beyla/v3/pkg/beyla"
)

func metricSelector(t *testing.T, cfg *obi.Config, groups attributes.AttrGroups) *attributes.AttrSelector {
	t.Helper()
	s, err := attributes.NewAttrSelector(groups, &attributes.SelectorConfig{
		SelectionCfg:            cfg.Attributes.Select,
		ExtraGroupAttributesCfg: cfg.Attributes.ExtraGroupAttributes,
		UseV2Selection:          cfg.Attributes.UseV2Selection,
	})
	require.NoError(t, err)
	return s
}

func TestHTTPServerMetricSelection(t *testing.T) {
	duration, request, response := attributes.HTTPServerDuration, attributes.HTTPServerRequestSize, attributes.HTTPServerResponseSize
	type endpoints map[attributes.Name][]attr.Name
	for _, tc := range []struct {
		name      string
		selection attributes.Selection
		extra     map[string][]attr.Name
		groups    attributes.AttrGroups
		want      endpoints
	}{
		{name: "defaults"},
		{name: "empty", selection: attributes.Selection{}},
		{name: "unrelated metric", selection: attributes.Selection{"http_client_*": {Include: []string{"server.*"}}}},
		{name: "exclude only", groups: attributes.GroupKubernetes, selection: attributes.Selection{"*": {Exclude: []string{"k8s.pod.*"}}}},
		{name: "existing endpoint exclusions", selection: attributes.Selection{"http_server_*": {Exclude: []string{"server_*"}}}},
		{name: "inherit defaults with one opt-in", selection: attributes.Selection{
			"*":              {Exclude: []string{"k8s.pod.*"}},
			duration.Section: {Include: []string{"server_address"}},
		}, want: endpoints{duration: {attr.ServerAddr}}},
		{name: "suffix wildcard and literal exclusion", selection: attributes.Selection{
			"http.server.request.duration*": {Include: []string{"http.request.method"}},
			duration.Section:                {Exclude: []string{"http.route"}},
		}},
		{name: "one address", selection: attributes.Selection{duration.Section: {Include: []string{"server.address"}}}, want: endpoints{duration: {attr.ServerAddr}}},
		{name: "one port", selection: attributes.Selection{"http_server_request_body_size_bytes_count": {Include: []string{"server_port"}}}, want: endpoints{request: {attr.ServerPort}}},
		{name: "both endpoints", selection: attributes.Selection{response.Section: {Include: []string{"server.*"}}}, want: endpoints{response: {attr.ServerAddr, attr.ServerPort}}},
		{name: "overlapping includes and excludes", selection: attributes.Selection{
			"*":                     {Exclude: []string{"k8s.pod.*"}},
			"http.server.*":         {Include: []string{"server_*"}},
			"http_server_request_*": {Exclude: []string{"server.address"}},
			duration.Section:        {Include: []string{"server_address"}, Exclude: []string{"server_port"}},
		}, want: endpoints{duration: {attr.ServerAddr}, request: {attr.ServerPort}, response: {attr.ServerAddr, attr.ServerPort}}},
		{name: "include all with narrower exclusion", selection: attributes.Selection{
			"*":             {Include: []string{"*"}},
			"http_server_*": {Exclude: []string{"server.port"}},
		}, want: endpoints{duration: {attr.ServerAddr}, request: {attr.ServerAddr}, response: {attr.ServerAddr}}},
		{name: "suffix wildcard replaces defaults", selection: attributes.Selection{
			"http_server_request_duration*": {Include: []string{"http.route"}},
		}},
		{name: "app opt-in and disabled k8s opt-in", extra: map[string][]attr.Name{
			"app": {attr.ServiceName, attr.ServerAddr}, "k8s_app_meta": {attr.ServerPort},
		}, want: endpoints{duration: {attr.ServerAddr}, request: {attr.ServerAddr}, response: {attr.ServerAddr}}},
		{name: "enabled k8s opt-in", groups: attributes.GroupKubernetes, extra: map[string][]attr.Name{
			"k8s_app_meta": {attr.ServerPort},
		}, selection: attributes.Selection{duration.Section: {Exclude: []string{"server.*"}}},
			want: endpoints{request: {attr.ServerPort}, response: {attr.ServerPort}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &obi.Config{}
			cfg.Attributes.Select = tc.selection
			cfg.Attributes.Select.Normalize()
			cfg.Attributes.ExtraGroupAttributes = tc.extra
			for _, v2 := range []bool{false, true} {
				cfg.Attributes.UseV2Selection = v2
				groups := tc.groups | attributes.GroupHTTPRoutes
				effective, err := applicationMetricConfig(cfg, groups)
				require.NoError(t, err)
				for _, exporter := range []attributes.AttrGroups{0, attributes.GroupPrometheus} {
					selected := metricSelector(t, effective, groups|exporter)
					original := metricSelector(t, cfg, groups|exporter)
					for _, m := range []attributes.Name{duration, request, response} {
						// The contract changes only the two endpoint defaults. Compare
						// every other label, including exporter-specific labels, with OBI.
						want := slices.DeleteFunc(original.For(m), func(a attr.Name) bool {
							return a == attr.ServerAddr || a == attr.ServerPort
						})
						want = append(want, tc.want[m]...)
						require.ElementsMatch(t, want, selected.For(m), "%s, exporter group %d, v2=%t", m.OTEL, exporter, v2)
					}
					for _, m := range []attributes.Name{attributes.HTTPClientDuration, attributes.HTTPClientRequestSize, attributes.HTTPClientResponseSize, attributes.RPCServerDuration, attributes.DBServerDuration, attributes.Traces} {
						require.Equal(t, original.For(m), selected.For(m), "%s, exporter group %d, v2=%t", m.Section, exporter, v2)
					}
				}
			}
		})
	}
}

func TestHTTPServerMetricConfigDocuments(t *testing.T) {
	v1, err := beyla.LoadConfig(strings.NewReader(`
attributes:
  select:
    http_server_request_duration:
      include: [server.port]
`))
	require.NoError(t, err)
	configs := map[string]*beyla.Config{"v1": v1}
	for _, section := range []string{"capture", "enrich"} {
		data := `file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    ` + section + `:
      attributes:
        select:
          http.server.request.duration:
            include: [server.port]
`
		loaded, err := configbridge.LoadV2([]byte(data))
		require.NoError(t, err)
		configs["v2 "+section] = beyla.FromOBI(loaded)
	}
	for name, cfg := range configs {
		t.Run(name, func(t *testing.T) {
			effective, err := applicationMetricConfig(cfg.AsOBI(), 0)
			require.NoError(t, err)
			s := metricSelector(t, effective, 0)
			require.Equal(t, []attr.Name{attr.ServerPort}, s.For(attributes.HTTPServerDuration))
			for _, m := range []attributes.Name{attributes.HTTPServerRequestSize, attributes.HTTPServerResponseSize} {
				require.NotContains(t, s.For(m), attr.ServerAddr)
				require.NotContains(t, s.For(m), attr.ServerPort)
			}
		})
	}
}

func TestHTTPServerMetricConfigIsolation(t *testing.T) {
	cfg := beyla.Config{}
	// Spare capacity detects appends that overwrite a caller's backing array.
	exclude := []string{"http.route", "sentinel", "sentinel"}
	const duration = "http[.]server.request.duration"
	cfg.Attributes.Select = attributes.Selection{duration: {Exclude: exclude[:1]}}
	cfg.Attributes.ExtraGroupAttributes = map[string][]attr.Name{"k8s_app_meta": {attr.ServerAddr}}
	cached := cfg.AsOBI()
	standalone, err := applicationMetricConfig(cached, 0)
	require.NoError(t, err)
	kube, err := applicationMetricConfig(cached, attributes.GroupKubernetes)
	require.NoError(t, err)
	require.Same(t, cached, cfg.AsOBI())
	require.Equal(t, []string{"http.route", "sentinel", "sentinel"}, exclude)
	require.Equal(t, attributes.Selection{duration: {Exclude: []string{"http.route"}}}, cfg.Attributes.Select)
	require.Equal(t, cfg.Attributes.Select, cached.Attributes.Select)
	require.NotContains(t, metricSelector(t, standalone, 0).For(attributes.HTTPServerDuration), attr.ServerAddr)
	require.Contains(t, metricSelector(t, kube, attributes.GroupKubernetes).For(attributes.HTTPServerDuration), attr.ServerAddr)
}

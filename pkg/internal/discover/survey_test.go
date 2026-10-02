package discover

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v3/pkg/beyla"
	servicesextra "github.com/grafana/beyla/v3/pkg/services"
)

func TestSurveyCriteriaPreservesSocketSelection(t *testing.T) {
	cfg, err := beyla.LoadConfig(strings.NewReader(`
discovery:
  survey:
    - exe_path: "/opt/apps/*"
      socket_apps: true
    - k8s_namespace: "prod-*"
    - socket_apps: true
`))
	require.NoError(t, err)
	criteria := surveyCriteria(cfg)
	require.Len(t, criteria, 3)
	for i, wantsSocket := range []bool{true, false, true} {
		selector, ok := criteria[i].(*servicesextra.SurveySelector)
		require.True(t, ok, "normalized selectors must retain the survey extension")
		assert.Equal(t, wantsSocket, selector.SocketApps)
	}
	assert.True(t, criteria[0].GetPath().MatchString("/opt/apps/worker"))
	assert.False(t, criteria[0].GetPath().MatchString("/usr/bin/system-service"))
	assert.True(t, criteria[1].GetPath().IsSet(), "preserve OBI's metadata-only normalization")
	assert.True(t, criteria[1].GetPath().MatchString("/app"))
	assert.True(t, criteria[2].GetPath().IsSet(), "socket-only criteria match any executable")
	assert.True(t, criteria[2].GetPath().MatchString("/app"))
	assert.False(t, cfg.Discovery.Survey[1].Path.IsSet(), "normalization must not mutate the configuration")
	assert.False(t, cfg.Discovery.Survey[2].Path.IsSet())
}

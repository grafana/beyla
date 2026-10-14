package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestSurveySelectorYAMLRoundTrip(t *testing.T) {
	const config = `
- exe_path: "/opt/apps/*"
  socket_apps:
    enabled: true
    non_root: true
  k8s_namespace: "prod-*"
  k8s_pod_labels:
    app: "worker-*"
- exe_path: "/opt/batch/*"
`
	var criteria SurveyDefinitionCriteria
	require.NoError(t, yaml.Unmarshal([]byte(config), &criteria))
	check := func(criteria SurveyDefinitionCriteria) {
		require.Len(t, criteria, 2)
		assert.True(t, criteria.SocketAppsEnabled())
		assert.True(t, criteria[0].SocketApps.Enabled)
		assert.True(t, criteria[0].SocketApps.NonRoot)
		assert.False(t, criteria[1].SocketApps.Enabled)
		assert.False(t, criteria[1].SocketApps.NonRoot)
		assert.True(t, criteria[0].Path.MatchString("/opt/apps/worker"))
		assert.False(t, criteria[0].Path.MatchString("/usr/bin/worker"))
		require.Contains(t, criteria[0].Metadata, "k8s_namespace")
		assert.True(t, criteria[0].Metadata["k8s_namespace"].MatchString("prod-eu"))
		assert.NotContains(t, criteria[0].Metadata, "socket_apps")
		require.Contains(t, criteria[0].PodLabels, "app")
		assert.True(t, criteria[0].PodLabels["app"].MatchString("worker-1"))
	}
	check(criteria)
	encoded, err := yaml.Marshal(criteria)
	require.NoError(t, err)
	var decoded SurveyDefinitionCriteria
	require.NoError(t, yaml.Unmarshal(encoded, &decoded))
	check(decoded)
}

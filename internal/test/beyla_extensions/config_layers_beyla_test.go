//go:build ignore

// Beyla layered configuration tests reuse the helpers of the generated config_reload_test.go.
// This file is copied to internal/testgenerated/integration/ by generate-obi-tests.sh

package integration

import (
	"bytes"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ti "go.opentelemetry.io/obi/pkg/test/integration"

	"github.com/grafana/beyla/v3/internal/testgenerated/integration/components/docker"
)

const configLayersV2FirstDefinition = `        - action: include
          match:
            process:
              open_ports: "18060"`

// TestConfigLayersV2BaseV1Override runs Beyla with `--config base.yml --config override.yml`
// where the base file is Config v2 and the override is a v1 file that raises the log level.
func TestConfigLayersV2BaseV1Override(t *testing.T) {
	base, err := os.ReadFile("configs/obi-config-reload-v2.yml")
	require.NoError(t, err)
	override, err := os.ReadFile("configs/beyla-config-layer-v1-override.yml")
	require.NoError(t, err)

	compose, configPath, httpClient := startBeylaConfigReloadFiles(t,
		map[string][]byte{"obi.yml": base, "override.yml": override},
		"docker-compose-config-layers.yml")

	waitForLayeredStartup(t, compose, httpClient, "v2")

	// The base is a v2 file, so a change in it must still refresh the discovery criteria,
	// while the log level of the override is kept.
	secondDefinition := strings.ReplaceAll(configLayersV2FirstDefinition, "18060", "18061")
	both := bytes.Replace(base, []byte(configLayersV2FirstDefinition),
		[]byte(configLayersV2FirstDefinition+"\n"+secondDefinition), 1)
	require.NotEqual(t, base, both, "the base fixture changed: update configLayersV2FirstDefinition")
	replaceReloadConfig(t, configPath, both)
	waitForReloadTrace(t, httpClient, "config-reload-b", configReloadServerB, "/layered-added-selection")
	waitForReloadTrace(t, httpClient, "config-reload-a", configReloadServerA, "/layered-retained-selection")
}

// TestConfigLayersV1BaseV2Override is the opposite: a v1 base that Beyla loads with its v1 semantics
// and a v2 override that raises the log level.
func TestConfigLayersV1BaseV2Override(t *testing.T) {
	base, err := os.ReadFile("configs/obi-config-reload.yml")
	require.NoError(t, err)
	override, err := os.ReadFile("configs/beyla-config-layer-v2-override.yml")
	require.NoError(t, err)

	compose, _, httpClient := startBeylaConfigReloadFiles(t,
		map[string][]byte{"obi.yml": base, "override.yml": override},
		"docker-compose-config-layers.yml")

	waitForLayeredStartup(t, compose, httpClient, "v1")
}

// waitForLayeredStartup checks that the files were layered: Beyla selects the base file
// version, it traces the selected service and logs at the level set by the override file,
// which differs from the one in the base file.
func waitForLayeredStartup(t *testing.T, compose *docker.Compose, httpClient *http.Client, version string) {
	t.Helper()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		ti.DoHTTPGetWithClient(ct, httpClient, configReloadServerB+"/ready", http.StatusOK)
	}, testTimeout, 250*time.Millisecond)
	waitForReloadTrace(t, httpClient, "config-reload-a", configReloadServerA, "/layered-initial")
	assertNoReloadTrace(t, httpClient, "config-reload-b", configReloadServerB, "/layered-initially-excluded")

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		logs, err := compose.LogsTail(500, "obi")
		require.NoError(ct, err)
		assert.Contains(ct, logs, "level=DEBUG", "the log level of the override file was not applied")
		assert.Regexp(ct, `configuration loaded.*version=`+version, logs)
	}, testTimeout, 250*time.Millisecond)
}

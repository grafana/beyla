//go:build ignore

// Beyla variant of OBI's TestConfigReload, which edits a Config v2 document that Beyla can't load.
// It reuses the helpers of the generated config_reload_test.go.
// This file is copied to internal/testgenerated/integration/ by generate-obi-tests.sh

package integration

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ti "go.opentelemetry.io/obi/pkg/test/integration"

	"github.com/grafana/beyla/v3/internal/testgenerated/integration/components/docker"
)

const configReloadV1FirstDefinition = `    - open_ports: 18060`

func TestConfigReloadV1(t *testing.T) {
	initial, err := os.ReadFile("configs/obi-config-reload.yml")
	require.NoError(t, err)
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "obi.yml")
	replaceReloadConfig(t, configPath, initial)

	compose, err := docker.ComposeSuite("docker-compose-config-reload.yml", filepath.Join(pathOutput, "test-suite-config-reload-v1.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env, "CONFIG_RELOAD_DIR="+configDir)
	t.Cleanup(func() { assert.NoError(t, compose.Close()) })
	require.NoError(t, compose.Up())

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		ti.DoHTTPGet(ct, configReloadServerB+"/ready", http.StatusOK)
	}, testTimeout, 250*time.Millisecond)
	waitForReloadTrace(t, "config-reload-a", configReloadServerA, "/initial-selection")
	assertNoReloadTrace(t, "config-reload-b", configReloadServerB, "/initially-excluded")

	cl, err := client.New(client.FromEnv)
	require.NoError(t, err)
	defer cl.Close()
	beylaID := testContainerID(t, cl, "hatest-obi")
	require.NotEmpty(t, beylaID)
	before, err := cl.ContainerInspect(t.Context(), beylaID, client.ContainerInspectOptions{})
	require.NoError(t, err)
	serverPIDs := map[string]uint64{
		"server-a": reloadServerPID(t, compose, "server-a"),
		"server-b": reloadServerPID(t, compose, "server-b"),
	}
	waitForReloadSelection(t, compose, serverPIDs, "server-a")

	secondDefinition := strings.ReplaceAll(configReloadV1FirstDefinition, "18060", "18061")
	both := bytes.Replace(initial, []byte(configReloadV1FirstDefinition),
		[]byte(configReloadV1FirstDefinition+"\n"+secondDefinition), 1)
	replaceReloadConfig(t, configPath, both)
	waitForReloadSelection(t, compose, serverPIDs, "server-a", "server-b")
	waitForReloadTrace(t, "config-reload-b", configReloadServerB, "/added-selection")
	waitForReloadTrace(t, "config-reload-a", configReloadServerA, "/retained-selection")

	t.Log("remove the first definition while retaining the second")
	onlyB := bytes.Replace(initial, []byte(configReloadV1FirstDefinition), []byte(secondDefinition), 1)
	replaceReloadConfig(t, configPath, onlyB)
	waitForReloadSelection(t, compose, serverPIDs, "server-b")
	waitForReloadTrace(t, "config-reload-b", configReloadServerB, "/retained-after-removal")
	assertNoReloadTrace(t, "config-reload-a", configReloadServerA, "/removed-selection")

	t.Log("reject a sampler change together with a selection change")
	incompatible := bytes.Replace(initial, []byte("name: always_on"), []byte("name: always_off"), 1)
	replaceReloadConfig(t, configPath, incompatible)
	waitForBeylaReloadRejection(t, compose)
	waitForReloadTrace(t, "config-reload-b", configReloadServerB, "/after-rejection")
	assertNoReloadTrace(t, "config-reload-a", configReloadServerA, "/rejected-selection")

	t.Log("accept a compatible edit after the rejection")
	replaceReloadConfig(t, configPath, initial)
	waitForReloadSelection(t, compose, serverPIDs, "server-a")
	waitForReloadTrace(t, "config-reload-a", configReloadServerA, "/recovered-selection")
	assertNoReloadTrace(t, "config-reload-b", configReloadServerB, "/excluded-after-recovery")

	after, err := cl.ContainerInspect(t.Context(), beylaID, client.ContainerInspectOptions{})
	require.NoError(t, err)
	assert.True(t, after.Container.State.Running)
	assert.Equal(t, before.Container.State.StartedAt, after.Container.State.StartedAt)
	assert.Zero(t, after.Container.RestartCount)
}

func waitForBeylaReloadRejection(t *testing.T, compose *docker.Compose) {
	t.Helper()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		logs, err := compose.LogsTail(200, "obi")
		require.NoError(ct, err)
		for line := range strings.SplitSeq(logs, "\n") {
			if strings.Contains(line, "level=ERROR") &&
				strings.Contains(line, "can't refresh configuration") &&
				strings.Contains(line, "restart Beyla") {
				return
			}
		}
		assert.Fail(ct, "Beyla did not log a refresh rejection requiring a restart")
	}, testTimeout, 250*time.Millisecond)
}

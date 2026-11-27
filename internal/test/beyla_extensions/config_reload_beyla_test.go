//go:build ignore

// Beyla config reload tests reuse the helpers of the generated config_reload_test.go.
// This file is copied to internal/testgenerated/integration/ by generate-obi-tests.sh

package integration

import (
	"bytes"
	"context"
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
	compose, configPath, httpClient := startBeylaConfigReload(t, initial)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		ti.DoHTTPGetWithClient(ct, httpClient, configReloadServerB+"/ready", http.StatusOK)
	}, testTimeout, 250*time.Millisecond)
	waitForReloadTrace(t, httpClient, "config-reload-a", configReloadServerA, "/initial-selection")
	assertNoReloadTrace(t, httpClient, "config-reload-b", configReloadServerB, "/initially-excluded")

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
	waitForReloadTrace(t, httpClient, "config-reload-b", configReloadServerB, "/added-selection")
	waitForReloadTrace(t, httpClient, "config-reload-a", configReloadServerA, "/retained-selection")

	t.Log("remove the first definition while retaining the second")
	onlyB := bytes.Replace(initial, []byte(configReloadV1FirstDefinition), []byte(secondDefinition), 1)
	replaceReloadConfig(t, configPath, onlyB)
	waitForReloadSelection(t, compose, serverPIDs, "server-b")
	waitForReloadTrace(t, httpClient, "config-reload-b", configReloadServerB, "/retained-after-removal")
	assertNoReloadTrace(t, httpClient, "config-reload-a", configReloadServerA, "/removed-selection")

	t.Log("add a service override while disabling global sampling")
	bothOff := bytes.Replace(both, []byte("name: always_on"), []byte("name: always_off"), 1)
	override := []byte(configReloadV1FirstDefinition + "\n      sampler: {name: always_on}")
	replaceReloadConfig(t, configPath, bytes.Replace(bothOff, []byte(configReloadV1FirstDefinition), override, 1))
	waitForReloadSelection(t, compose, serverPIDs, "server-a", "server-b")
	waitForReloadSampler(t, compose, "server-a", configReloadAlwaysSampled)
	waitForReloadSampler(t, compose, "server-b", configReloadNeverSampled)
	waitForReloadTrace(t, httpClient, "config-reload-a", configReloadServerA, "/override-on")
	assertNoReloadTrace(t, httpClient, "config-reload-b", configReloadServerB, "/global-off")

	t.Log("remove the override and use the current global sampler")
	replaceReloadConfig(t, configPath, bothOff)
	waitForReloadSampler(t, compose, "server-a", configReloadNeverSampled)
	assertNoReloadTrace(t, httpClient, "config-reload-a", configReloadServerA, "/override-removed")

	replaceReloadConfig(t, configPath, onlyB)
	waitForReloadSelection(t, compose, serverPIDs, "server-b")
	waitForReloadSampler(t, compose, "server-b", configReloadAlwaysSampled)
	waitForReloadTrace(t, httpClient, "config-reload-b", configReloadServerB, "/global-on")

	t.Log("reject sampler and selection changes combined with a log level change")
	incompatible := bytes.Replace(initial, []byte("name: always_on"), []byte("name: always_off"), 1)
	incompatible = bytes.Replace(incompatible, []byte("log_level: info"), []byte("log_level: debug"), 1)
	replaceReloadConfig(t, configPath, incompatible)
	waitForBeylaReloadRejection(t, compose, "restart Beyla")
	waitForReloadTrace(t, httpClient, "config-reload-b", configReloadServerB, "/after-rejection")
	assertNoReloadTrace(t, httpClient, "config-reload-a", configReloadServerA, "/rejected-selection")

	t.Log("accept a compatible edit after the rejection")
	replaceReloadConfig(t, configPath, initial)
	waitForReloadSelection(t, compose, serverPIDs, "server-a")
	waitForReloadTrace(t, httpClient, "config-reload-a", configReloadServerA, "/recovered-selection")
	assertNoReloadTrace(t, httpClient, "config-reload-b", configReloadServerB, "/excluded-after-recovery")
}

func TestConfigReloadInstrumentAllLocalSampling(t *testing.T) {
	initial, err := os.ReadFile("configs/beyla-config-reload-instrument-all-local.yml")
	require.NoError(t, err)
	compose, configPath, httpClient := startBeylaConfigReload(t, initial, "docker-compose-config-reload-instrument-all-local.yml")

	const (
		service        = "config-reload-a"
		sampledOutPath = "/local-sampled-out"
		quarterSampled = configReloadAlwaysSampled / 4
	)
	waitForReloadTrace(t, httpClient, service, configReloadServerA, "/local-initially-on")

	replaceReloadConfig(t, configPath, bytes.Replace(initial, []byte("name: always_on"), []byte("name: always_off"), 1))
	// Wait for the selected PID to apply the edit before sending requests that must be sampled out.
	waitForReloadSampler(t, compose, "server-a", configReloadNeverSampled)
	assertNoReloadTrace(t, httpClient, service, configReloadServerA, sampledOutPath)

	replaceReloadConfig(t, configPath, initial)
	waitForReloadSampler(t, compose, "server-a", configReloadAlwaysSampled)
	waitForReloadTrace(t, httpClient, service, configReloadServerA, "/local-sampled-again")

	// Check Jaeger for delayed spans from the requests made while sampling was off.
	require.Never(t, func() bool {
		trace, err := reloadTrace(service, sampledOutPath)
		if !assert.NoError(t, err) {
			return true
		}
		return trace.TraceID != ""
	}, 3*time.Second, 250*time.Millisecond, "trace appeared for %s after sampling resumed", sampledOutPath)

	ratio := bytes.Replace(initial, []byte("name: always_on"), []byte("name: traceidratio\n    arg: \"0.25\""), 1)
	replaceReloadConfig(t, configPath, ratio)
	waitForReloadSampler(t, compose, "server-a", quarterSampled)

	replaceReloadConfig(t, configPath, bytes.Replace(ratio, []byte("0.25"), []byte("0,25"), 1))
	waitForBeylaReloadRejection(t, compose, "otel_traces_export.sampler")
	waitForReloadSampler(t, compose, "server-a", quarterSampled)
}

func startBeylaConfigReload(t *testing.T, initial []byte, overrides ...string) (*docker.Compose, string, *http.Client) {
	t.Helper()
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "obi.yml")
	replaceReloadConfig(t, configPath, initial)

	require.NoError(t, os.MkdirAll(pathOutput, 0o755))
	compose, err := docker.ComposeSuiteWithOverrides("docker-compose-config-reload.yml", filepath.Join(pathOutput, t.Name()+".log"), overrides...)
	require.NoError(t, err)
	compose.Env = append(compose.Env, "CONFIG_RELOAD_DIR="+configDir)
	t.Cleanup(func() { assert.NoError(t, compose.Close()) })
	require.NoError(t, compose.Up())

	cl, err := client.New(client.FromEnv)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, cl.Close()) })
	// Docker gives this fixture its short container ID as the hostname.
	beylaID, err := compose.ExecOutput("obi", "cat", "/etc/hostname")
	require.NoError(t, err)
	before, err := cl.ContainerInspect(t.Context(), beylaID, client.ContainerInspectOptions{})
	require.NoError(t, err)
	t.Cleanup(func() {
		after, err := cl.ContainerInspect(context.Background(), beylaID, client.ContainerInspectOptions{})
		require.NoError(t, err)
		assert.True(t, after.Container.State.Running)
		assert.Equal(t, before.Container.State.StartedAt, after.Container.State.StartedAt)
		assert.Zero(t, after.Container.RestartCount)
	})

	// latchsrv serves one connection at a time, so it must close each connection before the next request.
	httpClient := &http.Client{
		Transport: &http.Transport{DisableKeepAlives: true},
		Timeout:   3 * time.Minute,
	}
	t.Cleanup(httpClient.CloseIdleConnections)
	return compose, configPath, httpClient
}

func waitForBeylaReloadRejection(t *testing.T, compose *docker.Compose, reason string) {
	t.Helper()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		logs, err := compose.LogsTail(200, "obi")
		require.NoError(ct, err)
		for line := range strings.SplitSeq(logs, "\n") {
			if strings.Contains(line, "level=ERROR") &&
				strings.Contains(line, "can't refresh configuration") &&
				strings.Contains(line, reason) {
				return
			}
		}
		assert.Failf(ct, "Beyla did not log the expected refresh rejection", "expected %q", reason)
	}, testTimeout, 250*time.Millisecond)
}

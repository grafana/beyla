//go:build integration

package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v3/internal/test/tools/docker"
	"github.com/grafana/beyla/v3/internal/test/tools/promtest"
)

func TestSurveySocketOptions(t *testing.T) {
	controlDir := t.TempDir()
	// The non-root fixtures must be able to publish readiness and command results.
	require.NoError(t, os.Chmod(controlDir, 0o777))
	require.NoError(t, os.MkdirAll(pathOutput, 0o755))
	compose, err := docker.ComposeSuite("compose/docker-compose-survey-options.yml", path.Join(pathOutput, "test-suite-survey-options.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env, "SURVEY_CONTROL_DIR="+controlDir,
		fmt.Sprintf("COMPOSE_PROJECT_NAME=beyla-survey-options-%d", os.Getpid()))
	t.Cleanup(func() { assert.NoError(t, compose.Close()) })
	require.NoError(t, compose.Up())
	portCmd := exec.CommandContext(t.Context(), "docker", "compose", "-f", compose.Path, "port", "prometheus", "9090")
	portCmd.Env = compose.Env
	port, err := portCmd.Output()
	require.NoError(t, err)

	fixtures := map[string]int{
		"ordinary-idle":       0,
		"socket-root-client":  0,
		"nonroot-idle":        1000,
		"nonroot-client":      1000,
		"nonroot-root-client": 0,
		"nonroot-root-1023":   0,
		"nonroot-root-1024":   0,
	}
	for name, uid := range fixtures {
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			ready, err := os.ReadFile(filepath.Join(controlDir, name+".ready"))
			require.NoError(ct, err)
			assert.Equal(ct, strconv.Itoa(uid), string(ready), "fixture %s must use the expected real UID", name)
		}, testTimeout, 100*time.Millisecond)
	}

	pq := promtest.Client{HostPort: strings.TrimSpace(string(port))}
	admitted := []string{"ordinary-idle", "socket-root-client", "nonroot-client", "nonroot-root-1023"}
	if !t.Run("initial selection", func(t *testing.T) {
		// The ordinary entry also matches a restrictive entry: survey entries
		// are alternatives, so the disabled socket filter must win even for root.
		waitForSurveyServices(t, &pq, admitted...)
		assertSurveyServicesAbsent(t, &pq, "nonroot-idle", "nonroot-root-client", "nonroot-root-1024")
	}) {
		return
	}

	if !t.Run("non-root client admitted after socket activity", func(t *testing.T) {
		surveyFixtureCommand(t, controlDir, "nonroot-idle", "connect nonroot-root-1024:1024")
		waitForSurveyServices(t, &pq, "nonroot-idle")
	}) {
		return
	}

	if !t.Run("root client admitted after privileged listen", func(t *testing.T) {
		// It already has a client socket, which is insufficient for non_root.
		// Opening port 1023 must promote the existing candidate without restarting it.
		surveyFixtureCommand(t, controlDir, "nonroot-root-client", "listen 1023")
		waitForSurveyServices(t, &pq, "nonroot-root-client")
		assertSurveyServicesAbsent(t, &pq, "nonroot-root-1024")
	}) {
		return
	}

	t.Run("closing sockets preserves admission", func(t *testing.T) {
		surveyFixtureCommand(t, controlDir, "nonroot-idle", "close")
		surveyFixtureCommand(t, controlDir, "nonroot-root-client", "close")
		waitForSurveyServices(t, &pq, "nonroot-idle", "nonroot-root-client")
		require.Never(t, func() bool {
			results, err := pq.Query(surveyServicesQuery("nonroot-idle", "nonroot-root-client"))
			assert.NoError(t, err)
			return err != nil || len(results) != 2
		}, 10*time.Second, 500*time.Millisecond, "admission must survive socket closure and periodic watcher recovery")
	})
}

func surveyServicesQuery(names ...string) string {
	return fmt.Sprintf(`survey_info{service_namespace="survey-options",service_name=~"%s"} > 0`, strings.Join(names, "|"))
}

func waitForSurveyServices(t *testing.T, pq *promtest.Client, names ...string) {
	t.Helper()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(surveyServicesQuery(names...))
		require.NoError(ct, err)
		var actual []string
		for _, result := range results {
			actual = append(actual, result.Metric["service_name"])
			assert.Equal(ct, "1", result.Value[1])
		}
		assert.ElementsMatch(ct, names, actual)
	}, testTimeout, 500*time.Millisecond)
}

func assertSurveyServicesAbsent(t *testing.T, pq *promtest.Client, names ...string) {
	t.Helper()
	// Positive assertions above prove the exporter is live. Observe exclusions
	// over multiple discovery polls, exports, scrapes, and watcher recovery cycles.
	require.Never(t, func() bool {
		results, err := pq.Query(surveyServicesQuery(names...))
		assert.NoError(t, err)
		return err != nil || len(results) != 0
	}, 10*time.Second, 500*time.Millisecond, "excluded services must not produce survey_info: %v", names)
}

func surveyFixtureCommand(t *testing.T, controlDir, name, command string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(controlDir, name+".command"), []byte(command), 0o644))
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		result, err := os.ReadFile(filepath.Join(controlDir, name+".result"))
		require.NoError(ct, err)
		assert.Equal(ct, command, string(result))
	}, testTimeout, 100*time.Millisecond)
}

//go:build integration

package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ti "go.opentelemetry.io/obi/pkg/test/integration"

	"github.com/grafana/beyla/v3/internal/test/tools/docker"
	"github.com/grafana/beyla/v3/internal/test/tools/promtest"
)

// TestInstrumentAllLocal verifies application instrumentation without survey reporting.
func TestInstrumentAllLocal(t *testing.T) {
	testInstrumentAllLocal(t, "beyla-config-instrument-all-local.yml", false)
}

// TestInstrumentAllLocalWithSurvey verifies independent survey and application selection.
func TestInstrumentAllLocalWithSurvey(t *testing.T) {
	testInstrumentAllLocal(t, "beyla-config-instrument-all-local-survey.yml", true)
}

// testInstrumentAllLocal checks per-process eligibility across multiple HTTP services.
func testInstrumentAllLocal(t *testing.T, config string, survey bool) {
	t.Helper()
	require.NoError(t, os.MkdirAll(pathOutput, 0o755))
	compose, err := docker.ComposeSuite("compose/docker-compose-instrument-all-local.yml", path.Join(pathOutput, t.Name()+".log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env, "BEYLA_TEST_CONFIG="+config,
		fmt.Sprintf("COMPOSE_PROJECT_NAME=beyla-local-%d-%s", os.Getpid(), strings.ToLower(t.Name())))
	t.Cleanup(func() { assert.NoError(t, compose.Close()) })
	require.NoError(t, compose.Up())

	pq := promtest.Client{HostPort: localComposeAddress(t, compose, "prometheus", "9090")}
	services := []struct {
		name string
		port string
	}{
		{name: "nonroot", port: "8080"},
		{name: "root-1023", port: "1023"},
		{name: "root-1024", port: "1024"},
		{name: "python-workers", port: "8080"},
	}
	var urls []string
	for _, service := range services {
		urls = append(urls, "http://"+localComposeAddress(t, compose, service.name, service.port)+"/local-instrumentation")
	}
	requests := func(ct require.TestingT) {
		for _, url := range urls {
			ti.DoHTTPGet(ct, url, 200)
		}
	}

	if survey && !t.Run("independent survey selection", func(t *testing.T) {
		waitForLocalServices(t, &pq, requests, "survey_info", "local-nonroot", "local-root-1023", "local-root-1024", "local-python-workers")
	}) {
		return
	}
	if !t.Run("eligible services produce application metrics", func(t *testing.T) {
		waitForLocalServices(t, &pq, requests, "http_server_request_duration_seconds_count", "local-nonroot", "local-root-1023", "local-python-workers")
		waitForLocalServices(t, &pq, requests, "target_info", "local-nonroot", "local-root-1023", "local-python-workers")
	}) {
		return
	}

	if !t.Run("all forked Python workers produce application metrics", func(t *testing.T) {
		waitForLocalInstances(t, &pq, requests, "http_server_request_duration_seconds_count", "local-python-workers", 3)
	}) {
		return
	}

	t.Run("idle processes and root high port are excluded", func(t *testing.T) {
		running := strings.Fields(localComposeOutput(t, compose, "ps", "--status", "running", "--services"))
		require.Subset(t, running, []string{"idle-nonroot", "idle-root", "python-workers"})
		excluded := []string{"local-root-1024", "local-idle-nonroot", "local-idle-root"}
		query := localServicesQuery("http_server_request_duration_seconds_count", excluded...)
		query += " or " + localServicesQuery("target_info", excluded...)
		query += " or " + localServicesQuery("survey_info", "local-idle-nonroot", "local-idle-root")
		if !survey {
			query += ` or survey_info{service_namespace="instrument-all-local"}`
		}
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			requests(t)
			results, err := pq.Query(query)
			require.NoError(t, err)
			require.Empty(t, results, "unexpected application or survey metrics")
			time.Sleep(500 * time.Millisecond)
		}
	})
}

// localComposeAddress resolves a service's dynamically published loopback port.
func localComposeAddress(t *testing.T, compose *docker.Compose, service, port string) string {
	t.Helper()
	return localComposeOutput(t, compose, "port", service, port)
}

// localComposeOutput runs an inspection command against this test's Compose project.
func localComposeOutput(t *testing.T, compose *docker.Compose, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "docker", append([]string{"compose", "-f", compose.Path}, args...)...)
	cmd.Env = compose.Env
	output, err := cmd.Output()
	require.NoError(t, err)
	return strings.TrimSpace(string(output))
}

// localServicesQuery selects positive metrics grouped by the fixture service names.
func localServicesQuery(metric string, names ...string) string {
	return fmt.Sprintf(`sum by (service_name) (%s{service_namespace="instrument-all-local",service_name=~"%s"}) > 0`, metric, strings.Join(names, "|"))
}

// waitForLocalServices generates traffic until every expected service exports the metric.
func waitForLocalServices(t *testing.T, pq *promtest.Client, requests func(require.TestingT), metric string, names ...string) {
	t.Helper()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		requests(ct)
		results, err := pq.Query(localServicesQuery(metric, names...))
		require.NoError(ct, err)
		var actual []string
		for _, result := range results {
			actual = append(actual, result.Metric["service_name"])
		}
		assert.ElementsMatch(ct, names, actual)
	}, testTimeout, 500*time.Millisecond)
}

// waitForLocalInstances checks that metrics identify every process in the worker pool.
func waitForLocalInstances(t *testing.T, pq *promtest.Client, requests func(require.TestingT), metric, name string, count int) {
	t.Helper()
	query := fmt.Sprintf(`sum by (instance) (%s{service_namespace="instrument-all-local",service_name="%s"}) > 0`, metric, name)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		requests(ct)
		results, err := pq.Query(query)
		require.NoError(ct, err)
		assert.Len(ct, results, count)
		for _, result := range results {
			assert.Regexp(ct, `:\d+$`, result.Metric["instance"])
		}
	}, testTimeout, 500*time.Millisecond)
}

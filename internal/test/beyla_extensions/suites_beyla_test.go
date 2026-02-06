//go:build beyla_extension

// Beyla-specific integration test suites
// This file is copied to internal/obi/test/integration/ by generate-obi-tests.sh

package integration

import (
	"path"
	"testing"

	"github.com/stretchr/testify/require"

	ti "go.opentelemetry.io/obi/pkg/test/integration"

	"github.com/grafana/beyla/v3/internal/obi/test/integration/components/docker"
)

// TestSuiteClient_Beyla is a Beyla-specific test for client HTTP library instrumentation
// NOTE: Named with _Beyla suffix to avoid conflict with OBI's TestSuiteClient
func TestSuiteClient_Beyla(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-client.yml", path.Join(pathOutput, "test-suite-client.log"))
	compose.Env = append(compose.Env, `BEYLA_EXECUTABLE_NAME=pingclient`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Client RED metrics", testREDMetricsForClientHTTPLibrary)
	require.NoError(t, compose.Close())
}

// TestSuiteClientPromScrape_Beyla is a Beyla-specific test for client HTTP library with Prometheus scrape
// NOTE: Named with _Beyla suffix to avoid conflict with OBI's TestSuiteClientPromScrape
// Uses a dedicated docker-compose that sets BEYLA_PROMETHEUS_FEATURES to include application_process,
// since the OBI upstream docker-compose-client.yml hardcodes features without it.
func TestSuiteClientPromScrape_Beyla(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-client-promscrape.yml", path.Join(pathOutput, "test-suite-client-promscrape.log"))
	compose.Env = append(compose.Env, `BEYLA_EXECUTABLE_NAME=pingclient`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Client RED metrics", testREDMetricsForClientHTTPLibraryNoTraces)
	t.Run("Testing Beyla Build Info metric", testPrometheusBeylaBuildInfo)
	t.Run("Testing Host Info metric", testHostInfo)
	t.Run("Testing process-level metrics", testProcesses(map[string]string{
		"process_executable_name": "pingclient",
		"process_executable_path": "/pingclient",
		"process_command":         "pingclient",
		"process_command_line":    "/pingclient",
	}))

	require.NoError(t, compose.Close())
}

// TestSuite_OpenPort_Beyla is a Beyla-specific test for open port discovery
// Same as Test suite, but searching the executable by port instead of executable name
// NOTE: Named with _Beyla suffix to avoid conflict if OBI adds this test
func TestSuite_OpenPort_Beyla(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-openport.log"))
	compose.Env = append(compose.Env, `BEYLA_OPEN_PORT=8080`, `BEYLA_EXECUTABLE_NAME=`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	config := testConfig()

	t.Run("RED metrics", testREDMetricsHTTP)
	t.Run("HTTP traces", testHTTPTraces)
	t.Run("GRPC traces", testGRPCTraces)
	t.Run("GRPC RED metrics", testREDMetricsGRPC)
	t.Run("Internal Prometheus metrics", func(t *testing.T) { ti.InternalPrometheusExport(t, config) })

	require.NoError(t, compose.Close())
}

// TestSuite_PythonSQL_Beyla is a Beyla-specific test for Python SQL instrumentation
// Uses both HTTP and SQL, but we want to see only SQL events, since we are filtering by SQL only
// NOTE: Named with _Beyla suffix to avoid conflict if OBI adds this test
func TestSuite_PythonSQL_Beyla(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python-sql.yml", path.Join(pathOutput, "test-suite-python-sql.log"))
	compose.Env = append(compose.Env, `BEYLA_OPEN_PORT=8080`, `BEYLA_EXECUTABLE_NAME=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Python SQL metrics", testREDMetricsPythonSQLOnly)
	require.NoError(t, compose.Close())
}

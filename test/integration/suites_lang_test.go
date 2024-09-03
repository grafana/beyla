//go:build integration_lang

package integration

import (
	"path"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/test/integration/components/docker"
)

func TestSuite_Java(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-java.yml", path.Join(pathOutput, "test-suite-java.log"))
	compose.Env = append(compose.Env, `JAVA_TEST_MODE=-native`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Java RED metrics", testREDMetricsJavaHTTP)
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

// Same as TestSuite_Java but we run in the process namespace and it uses process namespace filtering
func TestSuite_Java_PID(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-java-pid.yml", path.Join(pathOutput, "test-suite-java-pid.log"))
	compose.Env = append(compose.Env, `JAVA_OPEN_PORT=8085`, `JAVA_EXECUTABLE_NAME=`, `JAVA_TEST_MODE=-jar`, `OTEL_SERVICE_NAME=greeting`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Java RED metrics", testREDMetricsJavaHTTP)
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

// same as Test suite for java, but using the system_wide instrumentation
// TODO: Fix the service name, mimir seems to work with what we have, but not Prometheus
func TestSuite_Java_SystemWide(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-java-system-wide.yml", path.Join(pathOutput, "test-suite-java-system-wide.log"))
	compose.Env = append(compose.Env, `BEYLA_SYSTEM_WIDE=TRUE`, `JAVA_EXECUTABLE_NAME=`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Java RED metrics", testREDMetricsJavaHTTPSystemWide)
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

// Same as Java Test suite, but searching the executable by port instead of executable name. We also run the jar version of Java instead of native image
func TestSuite_Java_OpenPort(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-java.yml", path.Join(pathOutput, "test-suite-java-openport.log"))
	compose.Env = append(compose.Env, `JAVA_OPEN_PORT=8085`, `JAVA_EXECUTABLE_NAME=`, `JAVA_TEST_MODE=-jar`, `OTEL_SERVICE_NAME=greeting`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Java RED metrics", testREDMetricsJavaHTTP)

	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

// Test that we can also instrument when running with host network mode
func TestSuite_Java_Host_Network(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-java-host.yml", path.Join(pathOutput, "test-suite-java-host-network.log"))
	compose.Env = append(compose.Env, `JAVA_TEST_MODE=-native`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Java RED metrics", testREDMetricsJavaHTTP)
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

func TestSuite_Rust(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-rust.yml", path.Join(pathOutput, "test-suite-rust.log"))
	compose.Env = append(compose.Env, `BEYLA_OPEN_PORT=8090`, `BEYLA_EXECUTABLE_NAME=`, `TEST_SERVICE_PORTS=8091:8090`, `TESTSERVER_IMAGE_VERSION=0.0.3`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Rust RED metrics", testREDMetricsRustHTTP)
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

func TestSuite_RustSSL(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-rust.yml", path.Join(pathOutput, "test-suite-rust-tls.log"))
	compose.Env = append(compose.Env, `BEYLA_OPEN_PORT=8490`, `BEYLA_EXECUTABLE_NAME=`, `TEST_SERVICE_PORTS=8491:8490`, `TESTSERVER_IMAGE_SUFFIX=-ssl`, `TESTSERVER_IMAGE_VERSION=0.0.3`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Rust RED metrics", testREDMetricsRustHTTPS)
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

// The actix server that we built our Rust example will enable HTTP2 for SSL automatically if the client supports it.
// We use this feature to implement our kprobes HTTP2 tests, with special http client settings that triggers the Go
// client to attempt http connection.
func TestSuite_RustHTTP2(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-rust.yml", path.Join(pathOutput, "test-suite-rust-http2.log"))
	compose.Env = append(compose.Env, `BEYLA_OPEN_PORT=8490`, `BEYLA_EXECUTABLE_NAME=`, `TEST_SERVICE_PORTS=8491:8490`, `TESTSERVER_IMAGE_SUFFIX=-ssl`, `TESTSERVER_IMAGE_VERSION=0.0.1`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Rust RED metrics", testREDMetricsRustHTTP2)
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

func TestSuite_NodeJS(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-nodejs.yml", path.Join(pathOutput, "test-suite-nodejs.log"))
	compose.Env = append(compose.Env, `BEYLA_OPEN_PORT=3030`, `BEYLA_EXECUTABLE_NAME=`, `NODE_APP=app`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("NodeJS RED metrics", testREDMetricsNodeJSHTTP)
	t.Run("HTTP traces (kprobes)", testHTTPTracesKProbes)
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

func TestSuite_NodeJSTLS(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-nodejs.yml", path.Join(pathOutput, "test-suite-nodejs-tls.log"))
	compose.Env = append(compose.Env, `BEYLA_OPEN_PORT=3033`, `BEYLA_EXECUTABLE_NAME=`, `NODE_APP=app_tls`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("NodeJS SSL RED metrics", testREDMetricsNodeJSHTTPS)
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

func TestSuite_Rails(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-ruby.yml", path.Join(pathOutput, "test-suite-ruby.log"))
	compose.Env = append(compose.Env, `BEYLA_OPEN_PORT=3040`, `BEYLA_EXECUTABLE_NAME=`, `TEST_SERVICE_PORTS=3041:3040`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Rails RED metrics", testREDMetricsRailsHTTP)
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

func TestSuite_RailsTLS(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-ruby.yml", path.Join(pathOutput, "test-suite-ruby-tls.log"))
	compose.Env = append(compose.Env, `BEYLA_OPEN_PORT=3043`, `BEYLA_EXECUTABLE_NAME=`, `TESTSERVER_IMAGE_SUFFIX=-ssl`, `TEST_SERVICE_PORTS=3044:3043`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Rails SSL RED metrics", testREDMetricsRailsHTTPS)
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

func TestSuite_DotNet(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-dotnet.yml", path.Join(pathOutput, "test-suite-dotnet.log"))
	compose.Env = append(compose.Env, `BEYLA_OPEN_PORT=5266`, `BEYLA_EXECUTABLE_NAME=`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("DotNet RED metrics", testREDMetricsDotNetHTTP)
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

// Disabled for now as we randomly fail to register 3 events, but only get 2
// Issue: https://github.com/grafana/beyla/issues/208
func TestSuite_DotNetTLS(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-dotnet.yml", path.Join(pathOutput, "test-suite-dotnet-tls.log"))
	compose.Env = append(compose.Env, `BEYLA_OPEN_PORT=7033`, `BEYLA_EXECUTABLE_NAME=`)
	// Add these above if you want to get the trace_pipe output in the test logs: `INSTRUMENT_DOCKERFILE_SUFFIX=_dbg`, `INSTRUMENT_COMMAND_SUFFIX=_wrapper.sh`
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("DotNet SSL RED metrics", testREDMetricsDotNetHTTPS)
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

func TestSuite_Python(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python.yml", path.Join(pathOutput, "test-suite-python.log"))
	compose.Env = append(compose.Env, `BEYLA_OPEN_PORT=8380`, `BEYLA_EXECUTABLE_NAME=`, `TEST_SERVICE_PORTS=8381:8380`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Python RED metrics", testREDMetricsPythonHTTP)
	t.Run("Python RED metrics with timeouts", testREDMetricsTimeoutPythonHTTP)
	t.Run("Checking process metrics", testProcesses(map[string]string{
		"process_executable_name": "python",
		"process_executable_path": "/usr/local/bin/python",
		"process_command":         "gunicorn",
		"process_command_line":    "/usr/local/bin/python /usr/local/bin/gunicorn -w 4 -b 0.0.0.0:8380 main:app --timeout 90",
	}))
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

// Uses both HTTP and SQL, but we want to see only SQL events, since we are filtering by SQL only
func TestSuite_PythonSQL(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python-sql.yml", path.Join(pathOutput, "test-suite-python-sql.log"))
	compose.Env = append(compose.Env, `BEYLA_OPEN_PORT=8080`, `BEYLA_EXECUTABLE_NAME=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Python SQL metrics", testREDMetricsPythonSQLOnly)
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

func TestSuite_PythonTLS(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python.yml", path.Join(pathOutput, "test-suite-python-tls.log"))
	compose.Env = append(compose.Env, `BEYLA_OPEN_PORT=8380`, `BEYLA_EXECUTABLE_NAME=`, `TEST_SERVICE_PORTS=8381:8380`, `TESTSERVER_DOCKERFILE_SUFFIX=_tls`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Python SSL RED metrics", testREDMetricsPythonHTTPS)
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

func TestSuiteNodeClient(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-nodeclient.yml", path.Join(pathOutput, "test-suite-nodeclient.log"))
	compose.Env = append(compose.Env, `BEYLA_EXECUTABLE_NAME=node`, `NODE_APP=client`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Node Client RED metrics", func(t *testing.T) {
		testNodeClientWithMethodAndStatusCode(t, "GET", 301, 80, "0000000000000000")
	})
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

func TestSuiteNodeClientTLS(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-nodeclient.yml", path.Join(pathOutput, "test-suite-nodeclient-tls.log"))
	compose.Env = append(compose.Env, `BEYLA_EXECUTABLE_NAME=node`, `NODE_APP=client_tls`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Node Client RED metrics", func(t *testing.T) {
		testNodeClientWithMethodAndStatusCode(t, "GET", 200, 443, "0000000000000001")
	})
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

func TestSuite_Elixir(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-elixir.yml", path.Join(pathOutput, "test-suite-elixir.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Elixir RED metrics", testREDMetricsElixirHTTP)
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

func TestSuite_OldestGoVersion(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-1.17.yml", path.Join(pathOutput, "test-suite-oldest-go.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("RED metrics", testREDMetricsOldHTTP)
	t.Run("HTTP traces", testHTTPTraces)
	t.Run("GRPC traces", testGRPCTraces)
	t.Run("GRPC RED metrics", testREDMetricsGRPC)
	t.Run("Internal Prometheus metrics", testInternalPrometheusExport)

	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

func TestSuite_UnsupportedGoVersion(t *testing.T) {
	t.Skip("seems flaky, we need to look into this")
	compose, err := docker.ComposeSuite("docker-compose-1.16.yml", path.Join(pathOutput, "test-suite-unsupported-go.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("RED metrics", testREDMetricsUnsupportedHTTP)
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

func TestSuite_SkipGoTracers(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-skip-go-tracers.log"))
	compose.Env = append(compose.Env, `BEYLA_SKIP_GO_SPECIFIC_TRACERS=1`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("RED metrics", testREDMetricsShortHTTP)
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

//go:build integration

package integration

import (
	"bufio"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/test/integration/components/docker"
)

func kprobeTracesEnabled() bool {
	major, minor := beyla.KernelVersion()

	return major > 5 || (major == 5 && minor >= 17)
}

func TestSuite(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("RED metrics", testREDMetricsHTTP)
	t.Run("HTTP traces", testHTTPTraces)
	t.Run("HTTP traces (no traceID)", testHTTPTracesNoTraceID)
	t.Run("GRPC traces", testGRPCTraces)
	t.Run("GRPC RED metrics", testREDMetricsGRPC)
	t.Run("GRPC TLS RED metrics", testREDMetricsGRPCTLS)
	t.Run("Internal Prometheus metrics", testInternalPrometheusExport)
	t.Run("Exemplars exist", testExemplarsExist)
	t.Run("Testing Host Info metric", testHostInfo)

	require.NoError(t, compose.Close())
}

func TestSuiteNestedTraces(t *testing.T) {
	// We run the test depending on what the host environment is. If the host is in lockdown mode integrity
	// the nesting of spans will be limited. If we are in none (which should be in any non secure boot environment, e.g. Virtual Machines or CI)
	// then we expect full nesting of trace spans in this test.

	// Echo (server) -> echo (client) -> EchoBack (server)
	lockdown := KernelLockdownMode()
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-nested.log"))
	if !lockdown {
		compose.Env = append(compose.Env, `SECURITY_CONFIG_SUFFIX=_none`)
	}
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	if !lockdown {
		t.Run("HTTP traces (all spans nested)", testHTTPTracesNestedClientWithContextPropagation)
		t.Run("HTTP -> gRPC traces (all spans nested)", testHTTP2GRPCTracesNestedCallsWithContextPropagation)
	} else {
		t.Run("HTTP traces (nested client span)", testHTTPTracesNestedClient)
		t.Run("HTTP -> gRPC traces (nested client span)", testHTTP2GRPCTracesNestedCallsNoPropagation)
	}
	require.NoError(t, compose.Close())
}

func TestSuiteClient(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-client.yml", path.Join(pathOutput, "test-suite-client.log"))
	compose.Env = append(compose.Env, `BEYLA_EXECUTABLE_NAME=pingclient`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Client RED metrics", testREDMetricsForClientHTTPLibrary)
	require.NoError(t, compose.Close())
}

func TestSuiteClientPromScrape(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-client.yml", path.Join(pathOutput, "test-suite-client-promscrape.log"))
	compose.Env = append(compose.Env, `BEYLA_EXECUTABLE_NAME=pingclient`)
	compose.Env = append(compose.Env,
		`INSTRUMENTER_CONFIG_SUFFIX=-promscrape`,
		`PROM_CONFIG_SUFFIX=-promscrape`,
	)
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

// Same as Test suite, but the generated test image does not contain debug information
func TestSuite_NoDebugInfo(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-nodebug.log"))
	compose.Env = append(compose.Env, `TESTSERVER_DOCKERFILE_SUFFIX=_nodebug`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("RED metrics", testREDMetricsHTTP)
	t.Run("HTTP traces", testHTTPTraces)
	t.Run("GRPC traces", testGRPCTraces)
	t.Run("GRPC RED metrics", testREDMetricsGRPC)
	t.Run("Internal Prometheus metrics", testInternalPrometheusExport)

	require.NoError(t, compose.Close())
}

// Same as Test suite, but the generated test image does not contain debug information
func TestSuite_StaticCompilation(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-static.log"))
	compose.Env = append(compose.Env, `TESTSERVER_DOCKERFILE_SUFFIX=_static`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("RED metrics", testREDMetricsHTTP)
	t.Run("HTTP traces", testHTTPTraces)
	t.Run("GRPC traces", testGRPCTraces)
	t.Run("GRPC RED metrics", testREDMetricsGRPC)
	t.Run("Internal Prometheus metrics", testInternalPrometheusExport)

	require.NoError(t, compose.Close())
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

	require.NoError(t, compose.Close())
}

func TestSuite_UnsupportedGoVersion(t *testing.T) {
	t.Skip("seems flaky, we need to look into this")
	compose, err := docker.ComposeSuite("docker-compose-1.16.yml", path.Join(pathOutput, "test-suite-unsupported-go.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("RED metrics", testREDMetricsUnsupportedHTTP)
	require.NoError(t, compose.Close())
}

func TestSuite_SkipGoTracers(t *testing.T) {
	t.Skip("seems flaky, we need to look into this")
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-skip-go-tracers.log"))
	compose.Env = append(compose.Env, `BEYLA_SKIP_GO_SPECIFIC_TRACERS=1`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("RED metrics", testREDMetricsShortHTTP)
	require.NoError(t, compose.Close())
}

func TestSuite_GRPCExport(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-grpc-export.log"))
	compose.Env = append(compose.Env, "INSTRUMENTER_CONFIG_SUFFIX=-grpc-export")
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("RED metrics", testREDMetricsHTTP)
	t.Run("trace HTTP service and export as GRPC traces", testHTTPTraces)
	t.Run("trace GRPC service and export as GRPC traces", testGRPCTraces)
	t.Run("GRPC RED metrics", testREDMetricsGRPC)

	require.NoError(t, compose.Close())
}

func TestSuite_GRPCExportKProbes(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-grpc-export-kprobes.log"))
	compose.Env = append(compose.Env, "INSTRUMENTER_CONFIG_SUFFIX=-grpc-export")
	compose.Env = append(compose.Env, `BEYLA_SKIP_GO_SPECIFIC_TRACERS=1`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	waitForTestComponents(t, instrumentedServiceStdURL)

	t.Run("trace GRPC service and export as GRPC traces - kprobes", testGRPCKProbeTraces)
	t.Run("GRPC RED metrics - kprobes", testREDMetricsGRPC)

	require.NoError(t, compose.Close())
}

// Same as Test suite, but searching the executable by port instead of executable name
func TestSuite_OpenPort(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-openport.log"))
	compose.Env = append(compose.Env, `BEYLA_OPEN_PORT=8080`, `BEYLA_EXECUTABLE_NAME=`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("RED metrics", testREDMetricsHTTP)
	t.Run("HTTP traces", testHTTPTraces)
	t.Run("GRPC traces", testGRPCTraces)
	t.Run("GRPC RED metrics", testREDMetricsGRPC)
	t.Run("Internal Prometheus metrics", testInternalPrometheusExport)

	require.NoError(t, compose.Close())
}

// Instead of submitting metrics via OTEL, exposes them as an autoinstrumenter:8999/metrics endpoint
// that is scraped by the Prometheus server
func TestSuite_PrometheusScrape(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-promscrape.log"))
	compose.Env = append(compose.Env,
		`INSTRUMENTER_CONFIG_SUFFIX=-promscrape`,
		`PROM_CONFIG_SUFFIX=-promscrape`,
		`BEYLA_EXECUTABLE_NAME=`,
		`BEYLA_OPEN_PORT=8082,8999`, // force Beyla self-instrumentation to ensure we don't do it
	)

	require.NoError(t, err)
	require.NoError(t, compose.Up())
	// checking process metrics before any other test lets us verify that even if an application
	// hasn't received any request, their processes are still instrumented
	t.Run("Testing process-level metrics", testProcesses(map[string]string{
		"process_executable_name": "testserver",
		"process_executable_path": "/testserver",
		"process_command":         "testserver",
		"process_command_line":    "/testserver",
	}))
	t.Run("RED metrics", testREDMetricsHTTP)
	t.Run("GRPC RED metrics", testREDMetricsGRPC)
	t.Run("Internal Prometheus metrics", testInternalPrometheusExport)
	t.Run("Testing Beyla Build Info metric", testPrometheusBeylaBuildInfo)
	t.Run("Testing for no Beyla self metrics", testPrometheusNoBeylaEvents)
	t.Run("Testing BPF metrics", testPrometheusBPFMetrics)

	require.NoError(t, compose.Close())
}

func TestSuite_Java(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-java.yml", path.Join(pathOutput, "test-suite-java.log"))
	compose.Env = append(compose.Env, `JAVA_TEST_MODE=-native`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Java RED metrics", testREDMetricsJavaHTTP)
	require.NoError(t, compose.Close())
}

// Same as TestSuite_Java but we run in the process namespace and it uses process namespace filtering
func TestSuite_Java_PID(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-java-pid.yml", path.Join(pathOutput, "test-suite-java-pid.log"))
	compose.Env = append(compose.Env, `JAVA_OPEN_PORT=8085`, `JAVA_EXECUTABLE_NAME=`, `JAVA_TEST_MODE=-jar`, `OTEL_SERVICE_NAME=greeting`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Java RED metrics", testREDMetricsJavaHTTP)
	require.NoError(t, compose.Close())
}

// same as Test suite for java, but using the system_wide instrumentation
// TODO: Fix the service name, mimir seems to work with what we have, but not Prometheus
func TestSuite_Java_SystemWide(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-java-system-wide.yml", path.Join(pathOutput, "test-suite-java-system-wide.log"))
	compose.Env = append(compose.Env, `BEYLA_SYSTEM_WIDE=TRUE`, `JAVA_EXECUTABLE_NAME=`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Java RED metrics", testREDMetricsJavaHTTPSystemWide)
	require.NoError(t, compose.Close())
}

// Same as Java Test suite, but searching the executable by port instead of executable name. We also run the jar version of Java instead of native image
func TestSuite_Java_OpenPort(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-java.yml", path.Join(pathOutput, "test-suite-java-openport.log"))
	compose.Env = append(compose.Env, `JAVA_OPEN_PORT=8085`, `JAVA_EXECUTABLE_NAME=`, `JAVA_TEST_MODE=-jar`, `OTEL_SERVICE_NAME=greeting`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Java RED metrics", testREDMetricsJavaHTTP)

	require.NoError(t, compose.Close())
}

// Test that we can also instrument when running with host network mode
func TestSuite_Java_Host_Network(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-java-host.yml", path.Join(pathOutput, "test-suite-java-host-network.log"))
	compose.Env = append(compose.Env, `JAVA_TEST_MODE=-native`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Java RED metrics", testREDMetricsJavaHTTP)
	require.NoError(t, compose.Close())
}

func TestSuite_JavaOTelSDK(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-java-agent.yml", path.Join(pathOutput, "test-suite-java-agent.log"))
	compose.Env = append(compose.Env, `JAVA_TEST_MODE=-jar`, `JAVA_OPEN_PORT=8085`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Java RED metrics with OTel SDK injection", testREDMetricsJavaOTelSDKHTTP)
	require.NoError(t, compose.Close())
}

func TestSuite_Rust(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-rust.yml", path.Join(pathOutput, "test-suite-rust.log"))
	compose.Env = append(compose.Env, `BEYLA_OPEN_PORT=8090`, `BEYLA_EXECUTABLE_NAME=`, `TEST_SERVICE_PORTS=8091:8090`, `TESTSERVER_IMAGE_VERSION=0.0.3`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Rust RED metrics", testREDMetricsRustHTTP)
	require.NoError(t, compose.Close())
}

func TestSuite_RustSSL(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-rust.yml", path.Join(pathOutput, "test-suite-rust-tls.log"))
	compose.Env = append(compose.Env, `BEYLA_OPEN_PORT=8490`, `BEYLA_EXECUTABLE_NAME=`, `TEST_SERVICE_PORTS=8491:8490`, `TESTSERVER_IMAGE_SUFFIX=-ssl`, `TESTSERVER_IMAGE_VERSION=0.0.3`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Rust RED metrics", testREDMetricsRustHTTPS)
	require.NoError(t, compose.Close())
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
	require.NoError(t, compose.Close())
}

func TestSuite_NodeJS(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-nodejs.yml", path.Join(pathOutput, "test-suite-nodejs.log"))
	compose.Env = append(compose.Env, `BEYLA_OPEN_PORT=3030`, `BEYLA_EXECUTABLE_NAME=`, `NODE_APP=app`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("NodeJS RED metrics", testREDMetricsNodeJSHTTP)
	t.Run("HTTP traces (kprobes)", testHTTPTracesKProbes)
	require.NoError(t, compose.Close())
}

func TestSuite_NodeJSTLS(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-nodejs.yml", path.Join(pathOutput, "test-suite-nodejs-tls.log"))
	compose.Env = append(compose.Env, `BEYLA_OPEN_PORT=3033`, `BEYLA_EXECUTABLE_NAME=`, `NODE_APP=app_tls`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("NodeJS SSL RED metrics", testREDMetricsNodeJSHTTPS)
	require.NoError(t, compose.Close())
}

func TestSuite_Rails(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-ruby.yml", path.Join(pathOutput, "test-suite-ruby.log"))
	compose.Env = append(compose.Env, `BEYLA_OPEN_PORT=3040`, `BEYLA_EXECUTABLE_NAME=`, `TEST_SERVICE_PORTS=3041:3040`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Rails RED metrics", testREDMetricsRailsHTTP)
	require.NoError(t, compose.Close())
}

func TestSuite_RailsTLS(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-ruby.yml", path.Join(pathOutput, "test-suite-ruby-tls.log"))
	compose.Env = append(compose.Env, `BEYLA_OPEN_PORT=3043`, `BEYLA_EXECUTABLE_NAME=`, `TESTSERVER_IMAGE_SUFFIX=-ssl`, `TEST_SERVICE_PORTS=3044:3043`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Rails SSL RED metrics", testREDMetricsRailsHTTPS)
	require.NoError(t, compose.Close())
}

func TestSuite_DotNet(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-dotnet.yml", path.Join(pathOutput, "test-suite-dotnet.log"))
	compose.Env = append(compose.Env, `BEYLA_OPEN_PORT=5266`, `BEYLA_EXECUTABLE_NAME=`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("DotNet RED metrics", testREDMetricsDotNetHTTP)
	require.NoError(t, compose.Close())
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
	require.NoError(t, compose.Close())
}

func TestSuite_Python(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python.yml", path.Join(pathOutput, "test-suite-python.log"))
	compose.Env = append(compose.Env, `BEYLA_OPEN_PORT=8380`, `BEYLA_EXECUTABLE_NAME=`, `TEST_SERVICE_PORTS=8381:8380`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	// checking process metrics before any other test lets us verify that even if an application
	// hasn't received any request, their processes are still instrumented
	t.Run("Checking process metrics", testProcesses(map[string]string{
		"process_executable_name": "python",
		"process_executable_path": "/usr/local/bin/python",
		"process_command":         "gunicorn",
		"process_command_line":    "/usr/local/bin/python /usr/local/bin/gunicorn -w 4 -b 0.0.0.0:8380 main:app --timeout 90",
	}))
	t.Run("Python RED metrics", testREDMetricsPythonHTTP)
	t.Run("Python RED metrics with timeouts", testREDMetricsTimeoutPythonHTTP)
	require.NoError(t, compose.Close())
}

// Uses both HTTP and SQL, but we want to see only SQL events, since we are filtering by SQL only
func TestSuite_PythonSQL(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python-sql.yml", path.Join(pathOutput, "test-suite-python-sql.log"))
	compose.Env = append(compose.Env, `BEYLA_OPEN_PORT=8080`, `BEYLA_EXECUTABLE_NAME=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Python SQL metrics", testREDMetricsPythonSQLOnly)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonSQLSSL(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python-sql-ssl.yml", path.Join(pathOutput, "test-suite-python-sql-ssl.log"))
	compose.Env = append(compose.Env, `BEYLA_OPEN_PORT=8080`, `BEYLA_EXECUTABLE_NAME=`, `TEST_SERVICE_PORTS=8381:8080`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Python SQL metrics", testREDMetricsPythonSQLSSL)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonTLS(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python.yml", path.Join(pathOutput, "test-suite-python-tls.log"))
	compose.Env = append(compose.Env, `BEYLA_OPEN_PORT=8380`, `BEYLA_EXECUTABLE_NAME=`, `TEST_SERVICE_PORTS=8381:8380`, `TESTSERVER_DOCKERFILE_SUFFIX=_tls`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Python SSL RED metrics", testREDMetricsPythonHTTPS)
	require.NoError(t, compose.Close())
}

func TestSuite_DisableKeepAlives(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-disablekeepalives.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	// Run tests with keepalives disabled:
	setHTTPClientDisableKeepAlives(true)
	t.Run("RED metrics", testREDMetricsHTTP)

	t.Run("HTTP DisableKeepAlives traces", testHTTPTraces)
	t.Run("Internal Prometheus DisableKeepAlives metrics", testInternalPrometheusExport)
	// Reset to defaults for any tests run afterward
	setHTTPClientDisableKeepAlives(false)

	require.NoError(t, compose.Close())
}

func TestSuite_OverrideServiceName(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-override-svcname.log"))
	compose.Env = append(compose.Env, "INSTRUMENTER_CONFIG_SUFFIX=-override-svcname")

	require.NoError(t, err)
	require.NoError(t, compose.Up())

	// Just few simple test cases to verify that the tracers properly override the service name
	// according to the configuration
	t.Run("RED metrics", func(t *testing.T) {
		waitForTestComponents(t, instrumentedServiceStdURL)
		testREDMetricsForHTTPLibrary(t, instrumentedServiceStdURL, "overridden-svc-name", "integration-test")
	})
	t.Run("GRPC traces", func(t *testing.T) {
		testGRPCTracesForServiceName(t, "overridden-svc-name")
	})

	require.NoError(t, compose.Close())
}

func TestSuiteNodeClient(t *testing.T) {
	if !kprobeTracesEnabled() {
		t.Skip("distributed traces not supported")
		return
	}

	compose, err := docker.ComposeSuite("docker-compose-nodeclient.yml", path.Join(pathOutput, "test-suite-nodeclient.log"))
	compose.Env = append(compose.Env, `BEYLA_EXECUTABLE_NAME=node`, `NODE_APP=client`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Node Client RED metrics", func(t *testing.T) {
		testNodeClientWithMethodAndStatusCode(t, "GET", 301, 80, "0000000000000000")
	})
	require.NoError(t, compose.Close())
}

func TestSuiteNodeClientTLS(t *testing.T) {
	if !kprobeTracesEnabled() {
		t.Skip("distributed traces not supported")
		return
	}

	compose, err := docker.ComposeSuite("docker-compose-nodeclient.yml", path.Join(pathOutput, "test-suite-nodeclient-tls.log"))
	compose.Env = append(compose.Env, `BEYLA_EXECUTABLE_NAME=node`, `NODE_APP=client_tls`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Node Client RED metrics", func(t *testing.T) {
		testNodeClientWithMethodAndStatusCode(t, "GET", 200, 443, "0000000000000001")
	})
	require.NoError(t, compose.Close())
}

func TestSuiteNoRoutes(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-no-routes.log"))
	compose.Env = append(compose.Env, "INSTRUMENTER_CONFIG_SUFFIX=-no-route")
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("RED metrics", testREDMetricsHTTPNoRoute)
	require.NoError(t, compose.Close())
}

func TestSuite_Elixir(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-elixir.yml", path.Join(pathOutput, "test-suite-elixir.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Elixir RED metrics", testREDMetricsElixirHTTP)
	require.NoError(t, compose.Close())
}

// Helpers

var lockdownPath = "/sys/kernel/security/lockdown"

func KernelLockdownMode() bool {
	// If we can't find the file, assume no lockdown
	if _, err := os.Stat(lockdownPath); err == nil {
		f, err := os.Open(lockdownPath)

		if err != nil {
			return true
		}

		defer f.Close()
		scanner := bufio.NewScanner(f)
		if scanner.Scan() {
			lockdown := scanner.Text()
			switch {
			case strings.Contains(lockdown, "[none]"):
				return false
			case strings.Contains(lockdown, "[integrity]"):
				return true
			case strings.Contains(lockdown, "[confidentiality]"):
				return true
			default:
				return true
			}
		}

		return true
	}

	return false
}

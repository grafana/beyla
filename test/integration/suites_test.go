//go:build integration

package integration

import (
	"path"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/test/integration/components/docker"
)

func TestSuite(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("RED metrics", testREDMetricsHTTP)
	t.Run("HTTP traces", testHTTPTraces)
	t.Run("HTTP traces (no traceID)", testHTTPTracesNoTraceID)
	t.Run("HTTP traces (bad traceparent)", testHTTPTracesBadTraceparent)
	t.Run("HTTP traces (kprobes)", testHTTPTracesKProbes)
	t.Run("GRPC traces", testGRPCTraces)
	t.Run("GRPC RED metrics", testREDMetricsGRPC)
	t.Run("Internal Prometheus metrics", testInternalPrometheusExport)

	t.Run("BPF pinning folder mounted", func(t *testing.T) { testBPFPinningMountedWithCount(t, 2) })
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

func TestSuiteClient(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-client.yml", path.Join(pathOutput, "test-suite-client.log"))
	compose.Env = append(compose.Env, `EXECUTABLE_NAME=pingclient`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Client RED metrics", testREDMetricsForClientHTTPLibrary)
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
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

	t.Run("BPF pinning folder mounted", func(t *testing.T) { testBPFPinningMountedWithCount(t, 2) })
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
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

	t.Run("BPF pinning folder mounted", func(t *testing.T) { testBPFPinningMountedWithCount(t, 2) })
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
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

	t.Run("BPF pinning folder mounted", func(t *testing.T) { testBPFPinningMountedWithCount(t, 2) })
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

// Same as Test suite, but searching the executable by port instead of executable name
func TestSuite_OpenPort(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-openport.log"))
	compose.Env = append(compose.Env, `OPEN_PORT=8080`, `EXECUTABLE_NAME=""`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("RED metrics", testREDMetricsHTTP)
	t.Run("HTTP traces", testHTTPTraces)
	t.Run("GRPC traces", testGRPCTraces)
	t.Run("GRPC RED metrics", testREDMetricsGRPC)
	t.Run("Internal Prometheus metrics", testInternalPrometheusExport)

	t.Run("BPF pinning folder mounted", func(t *testing.T) { testBPFPinningMountedWithCount(t, 2) })
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

// Instead of submitting metrics via OTEL, exposes them as an autoinstrumenter:8999/metrics endpoint
// that is scraped by the Prometheus server
func TestSuite_PrometheusScrape(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-promscrape.log"))
	compose.Env = append(compose.Env,
		`INSTRUMENTER_CONFIG_SUFFIX=-promscrape`,
		`PROM_CONFIG_SUFFIX=-promscrape`,
	)

	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("RED metrics", testREDMetricsHTTP)
	t.Run("GRPC RED metrics", testREDMetricsGRPC)
	t.Run("Internal Prometheus metrics", testInternalPrometheusExport)

	t.Run("BPF pinning folder mounted", func(t *testing.T) { testBPFPinningMountedWithCount(t, 2) })
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

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
	compose.Env = append(compose.Env, `JAVA_OPEN_PORT=8085`, `JAVA_EXECUTABLE_NAME=""`, `JAVA_TEST_MODE=-jar`, `OTEL_SERVICE_NAME=greeting`)
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
	compose, err := docker.ComposeSuite("docker-compose-java.yml", path.Join(pathOutput, "test-suite-java-system-wide.log"))
	compose.Env = append(compose.Env, `SYSTEM_WIDE=TRUE`, `JAVA_EXECUTABLE_NAME=`, `JAVA_TEST_MODE=-native`)
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
	compose.Env = append(compose.Env, `JAVA_OPEN_PORT=8085`, `JAVA_EXECUTABLE_NAME=""`, `JAVA_TEST_MODE=-jar`, `OTEL_SERVICE_NAME=greeting`)
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
	compose.Env = append(compose.Env, `OPEN_PORT=8090`, `EXECUTABLE_NAME=`, `TEST_SERVICE_PORTS=8091:8090`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Rust RED metrics", testREDMetricsRustHTTP)
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

func TestSuite_RustSSL(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-rust.yml", path.Join(pathOutput, "test-suite-rust-tls.log"))
	compose.Env = append(compose.Env, `OPEN_PORT=8490`, `EXECUTABLE_NAME=`, `TEST_SERVICE_PORTS=8491:8490`, `TESTSERVER_IMAGE_SUFFIX=-ssl`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Rust RED metrics", testREDMetricsRustHTTPS)
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

func TestSuite_NodeJS(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-nodejs.yml", path.Join(pathOutput, "test-suite-nodejs.log"))
	compose.Env = append(compose.Env, `OPEN_PORT=3030`, `EXECUTABLE_NAME=`, `TEST_SERVICE_PORTS=3031:3030`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("NodeJS RED metrics", testREDMetricsNodeJSHTTP)
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

func TestSuite_NodeJSTLS(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-nodejs.yml", path.Join(pathOutput, "test-suite-nodejs-tls.log"))
	compose.Env = append(compose.Env, `OPEN_PORT=3033`, `EXECUTABLE_NAME=`, `TESTSERVER_DOCKERFILE_SUFFIX=_tls`, `TEST_SERVICE_PORTS=3034:3033`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("NodeJS SSL RED metrics", testREDMetricsNodeJSHTTPS)
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

func TestSuite_Rails(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-ruby.yml", path.Join(pathOutput, "test-suite-ruby.log"))
	compose.Env = append(compose.Env, `OPEN_PORT=3040`, `EXECUTABLE_NAME=`, `TEST_SERVICE_PORTS=3041:3040`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Rails RED metrics", testREDMetricsRailsHTTP)
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

func TestSuite_RailsTLS(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-ruby.yml", path.Join(pathOutput, "test-suite-ruby-tls.log"))
	compose.Env = append(compose.Env, `OPEN_PORT=3043`, `EXECUTABLE_NAME=`, `TESTSERVER_IMAGE_SUFFIX=-tls`, `TEST_SERVICE_PORTS=3044:3043`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Rails SSL RED metrics", testREDMetricsRailsHTTPS)
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

func TestSuite_DotNet(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-dotnet.yml", path.Join(pathOutput, "test-suite-dotnet.log"))
	compose.Env = append(compose.Env, `OPEN_PORT=5266`, `EXECUTABLE_NAME=`, `TEST_SERVICE_PORTS=5267:5266`)
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
	compose.Env = append(compose.Env, `OPEN_PORT=7033`, `EXECUTABLE_NAME=`, `TEST_SERVICE_PORTS=7034:7033`, `TESTSERVER_DOCKERFILE_SUFFIX=_tls`)
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
	compose.Env = append(compose.Env, `OPEN_PORT=8080`, `EXECUTABLE_NAME=`, `TEST_SERVICE_PORTS=8081:8080`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Python RED metrics", testREDMetricsPythonHTTP)
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

func TestSuite_PythonTLS(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-python.yml", path.Join(pathOutput, "test-suite-python-tls.log"))
	compose.Env = append(compose.Env, `OPEN_PORT=8080`, `EXECUTABLE_NAME=`, `TEST_SERVICE_PORTS=8081:8080`, `TESTSERVER_DOCKERFILE_SUFFIX=_tls`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Python SSL RED metrics", testREDMetricsPythonHTTPS)
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
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

	t.Run("BPF pinning folder mounted", func(t *testing.T) { testBPFPinningMountedWithCount(t, 2) })
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
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
		testREDMetricsForHTTPLibrary(t, instrumentedServiceStdURL, "overridden-svc-name")
	})
	t.Run("GRPC traces", func(t *testing.T) {
		testGRPCTracesForServiceName(t, "overridden-svc-name")
	})

	t.Run("BPF pinning folder mounted", func(t *testing.T) { testBPFPinningMountedWithCount(t, 2) })
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

func TestSuiteNodeClient(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-nodeclient.yml", path.Join(pathOutput, "test-suite-nodeclient.log"))
	compose.Env = append(compose.Env, `EXECUTABLE_NAME=node`)
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
	compose.Env = append(compose.Env, `EXECUTABLE_NAME=node`, `TESTS_DOCKERFILE_SUFFIX=_tls`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Node Client RED metrics", func(t *testing.T) {
		testNodeClientWithMethodAndStatusCode(t, "GET", 200, 443, "0000000000000001")
	})
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

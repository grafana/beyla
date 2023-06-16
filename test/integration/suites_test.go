//go:build integration

package integration

import (
	"path"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/ebpf-autoinstrument/test/integration/components/docker"
)

func TestSuite(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("RED metrics", testREDMetricsHTTP)
	t.Run("HTTP traces", testHTTPTraces)
	t.Run("GRPC traces", testGRPCTraces)
	t.Run("GRPC RED metrics", testREDMetricsGRPC)
	t.Run("Internal Prometheus metrics", testInternalPrometheusExport)

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

	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
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

	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
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

	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
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
	compose.Env = append(compose.Env, `OPEN_PORT=8090`, `EXECUTABLE_NAME=`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Rust RED metrics", testREDMetricsRustHTTP)
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

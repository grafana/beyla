//go:build integration

package integration

import (
	"bufio"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/test/integration/components/docker"
)

var kprobeTraces = true // allow tests to run distributed traces tests

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

	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
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
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

func TestSuiteClient(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-client.yml", path.Join(pathOutput, "test-suite-client.log"))
	compose.Env = append(compose.Env, `BEYLA_EXECUTABLE_NAME=pingclient`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Client RED metrics", testREDMetricsForClientHTTPLibrary)
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
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
	t.Run("Testing process-level metrics", testProcesses(map[string]string{
		"process_executable_name": "pingclient",
		"process_executable_path": "/pingclient",
		"process_command":         "pingclient",
		"process_command_line":    "/pingclient",
	}))

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

	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
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

	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
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

	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
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
		`BEYLA_EXECUTABLE_NAME=`,
		`BEYLA_OPEN_PORT=8082,8999`, // force Beyla self-instrumentation to ensure we don't do it
	)

	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("RED metrics", testREDMetricsHTTP)
	t.Run("GRPC RED metrics", testREDMetricsGRPC)
	t.Run("Internal Prometheus metrics", testInternalPrometheusExport)
	t.Run("Testing Beyla Build Info metric", testPrometheusBeylaBuildInfo)
	t.Run("Testing for no Beyla self metrics", testPrometheusNoBeylaEvents)
	t.Run("Testing process-level metrics", testProcesses(map[string]string{
		"process_executable_name": "testserver",
		"process_executable_path": "/testserver",
		"process_command":         "testserver",
		"process_command_line":    "/testserver",
	}))

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

	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
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
		testREDMetricsForHTTPLibrary(t, instrumentedServiceStdURL, "overridden-svc-name", "integration-test")
	})
	t.Run("GRPC traces", func(t *testing.T) {
		testGRPCTracesForServiceName(t, "overridden-svc-name")
	})

	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

func TestSuiteNoRoutes(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-no-routes.log"))
	compose.Env = append(compose.Env, "INSTRUMENTER_CONFIG_SUFFIX=-no-route")
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("RED metrics", testREDMetricsHTTPNoRoute)
	t.Run("BPF pinning folder mounted", testBPFPinningMounted)
	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
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

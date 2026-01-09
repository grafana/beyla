//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"path"
	"strconv"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v2/internal/test/integration/components/docker"
	"github.com/grafana/beyla/v2/internal/test/integration/components/prom"
)

func TestMultiProcess(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-multiexec.yml", path.Join(pathOutput, "test-suite-multiexec.log"))
	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `BEYLA_EXECUTABLE_NAME=`, `BEYLA_OPEN_PORT=`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	t.Run("Go RED metrics: usual service", func(t *testing.T) {
		waitForTestComponents(t, instrumentedServiceStdURL)
		testREDMetricsForHTTPLibrary(t, instrumentedServiceStdURL, "testserver", "initial-set")
		// checks that, instrumenting the process from this container,
		// it doesn't instrument too the process from the other container
		checkReportedOnlyOnce(t, instrumentedServiceStdURL, "testserver")
	})
	t.Run("Go RED metrics: service 1", func(t *testing.T) {
		waitForTestComponents(t, "http://localhost:8900")
		testREDMetricsForHTTPLibrary(t, "http://localhost:8900", "rename1", "initial-set")
		// checks that, instrumenting the process from this container,
		// it doesn't instrument too the process from the other container
		checkReportedOnlyOnce(t, "http://localhost:8900", "rename1")
	})

	t.Run("Go RED metrics: rust service ssl", func(t *testing.T) {
		waitForTestComponents(t, "https://localhost:8491")
		testREDMetricsForRustHTTPLibrary(t, "https://localhost:8491", "rust-service-ssl", "multi-k", 8490, true)
		checkReportedRustEvents(t, "rust-service-ssl", "multi-k", 4)
	})

	t.Run("Go RED metrics: python service ssl", func(t *testing.T) {
		waitForTestComponents(t, "https://localhost:8381")
		testREDMetricsForPythonHTTPLibrary(t, "https://localhost:8381", "python-service-ssl", "multi-k")
		checkReportedPythonEvents(t, "python-service-ssl", "multi-k", 4)
	})

	t.Run("Go RED metrics: node service ssl", func(t *testing.T) {
		waitForTestComponents(t, "https://localhost:3034")
		testREDMetricsForNodeHTTPLibrary(t, "https://localhost:3034", "/greeting", "nodejs-service-ssl", "multi-k")
		checkReportedNodeJSEvents(t, "/greeting", "nodejs-service-ssl", "multi-k", 4)
	})

	t.Run("Go RED metrics: node service", func(t *testing.T) {
		waitForTestComponents(t, "http://localhost:3031")
		testREDMetricsForNodeHTTPLibrary(t, "http://localhost:3031", "/bye", "nodejs-service", "multi-k")
		checkReportedNodeJSEvents(t, "/bye", "nodejs-service", "multi-k", 4)
	})

	// do some requests to the server at port 18090, which must not be instrumented
	// as the instrumenter-config-multiexec.yml file only selects the process with port 18080.
	// Doing it early to give time to generate the traces (in case the test failed)
	// while doing another test in between for the same container
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		resp, err := http.Get("http://localhost:18090/dont-instrument")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("Processes in the same host are instrumented once and only once", func(t *testing.T) {
		waitForTestComponents(t, "http://localhost:18080")
		checkReportedOnlyOnce(t, "http://localhost:18080", "some-server")
	})

	// testing the earlier invocations to /dont-instrument
	t.Run("Non-selected processes must not be instrumented"+
		" even if they share the executable of another instrumented process", func(t *testing.T) {
		pq := prom.Client{HostPort: prometheusHostPort}
		results, err := pq.Query(`http_server_request_duration_seconds_count{url_path="/dont-instrument"}`)
		require.NoError(t, err)
		assert.Empty(t, results)
	})

	if kprobeTracesEnabled() {
		t.Run("Nested traces with kprobes: rust -> java -> node -> go -> python -> rails", func(t *testing.T) {
			testNestedHTTPTracesKProbes(t)
		})

		t.Run("Nested traces with kprobes: SSL node python rails", func(t *testing.T) {
			testNestedHTTPSTracesKProbes(t)
		})
	}

	t.Run("Instrumented processes metric", func(t *testing.T) {
		checkInstrumentedProcessesMetric(t)
	})

	require.NoError(t, compose.Close())
}

func TestMultiProcessAppCP(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-multiexec-host.yml", path.Join(pathOutput, "test-suite-multiexec-app-cp.log"))
	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `BEYLA_BPF_DISABLE_BLACK_BOX_CP=1`, `BEYLA_BPF_CONTEXT_PROPAGATION=all`, `BEYLA_BPF_TRACK_REQUEST_HEADERS=1`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	if kprobeTracesEnabled() {
		t.Run("Nested traces with kprobes: rust -> java -> node -> go -> python -> rails", func(t *testing.T) {
			testNestedHTTPTracesKProbes(t)
		})
	}
	require.NoError(t, compose.Close())
}

func TestMultiProcessAppCPNoIP(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-multiexec-host.yml", path.Join(pathOutput, "test-suite-multiexec-app-cp-no-ip.log"))
	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `BEYLA_BPF_DISABLE_BLACK_BOX_CP=1`, `BEYLA_BPF_CONTEXT_PROPAGATION=headers`, `BEYLA_BPF_TRACK_REQUEST_HEADERS=1`)

	require.NoError(t, err)
	require.NoError(t, compose.Up())

	if kprobeTracesEnabled() {
		t.Run("Nested traces with kprobes: rust -> java -> node -> go -> python -> rails", func(t *testing.T) {
			testNestedHTTPTracesKProbes(t)
		})
	}
	require.NoError(t, compose.Close())
}

// Addresses bug https://github.com/grafana/beyla/issues/370 for Go executables
// Prevents that two instances of the same process report traces or metrics by duplicate
func checkReportedOnlyOnce(t *testing.T, baseURL, serviceName string) {
	const path = "/check-only-once"
	for i := 0; i < 3; i++ {
		resp, err := http.Get(baseURL + path)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	}
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_name="` + serviceName + `",` +
			`url_path="` + path + `"}`)
		require.NoError(t, err)
		// check duration_count has 3 calls and all the arguments
		require.Len(t, results, 1)
		assert.Equal(t, 3, totalPromCount(t, results))
	}, test.Interval(1000*time.Millisecond))
}

func checkInstrumentedProcessesMetric(t *testing.T) {
	pq := prom.Client{HostPort: prometheusHostPort}
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		// we expected to have this in Prometheus at this point
		processes := map[string]int{
			"python3.11":    10,
			"greetings":     2,
			"java":          1,
			"node":          2,
			"ruby":          2,
			"duped_service": 1,
			"testserver":    2,
			"rename1":       1,
		}

		for processName, expectedCount := range processes {
			results, err := pq.Query(fmt.Sprintf(`beyla_instrumented_processes{process_name="%s"}`, processName))
			require.NoError(t, err)
			require.NotEmpty(t, results, "Expected to find instrumented processes metric for %s", processName)
			value, err := strconv.Atoi(results[0].Value[1].(string))
			require.NoError(t, err)
			assert.Equal(t, expectedCount, value)
		}
	}, test.Interval(1000*time.Millisecond))
}

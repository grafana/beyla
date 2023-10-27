//go:build integration

package integration

import (
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/test/integration/components/docker"
	"github.com/grafana/beyla/test/integration/components/prom"
)

func TestMultiProcess(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-multiexec.yml", path.Join(pathOutput, "test-suite-multiexec.log"))
	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `EXECUTABLE_NAME=`, `OPEN_PORT=`)
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
		results, err := pq.Query(`http_server_duration_seconds_count{http_target="/dont-instrument"}`)
		require.NoError(t, err)
		assert.Empty(t, results)
	})

	t.Run("BPF pinning folders mounted", func(t *testing.T) {
		// 1 pinned map for testserver and testserver-unused containers
		// 1 pinned map for testserver1 container
		// 1 pinned map for testserver-duplicate container
		testBPFPinningMountedWithCount(t, 3)
	})

	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
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
		results, err = pq.Query(`http_server_duration_seconds_count{` +
			`http_method="GET",` +
			`http_status_code="200",` +
			`service_name="` + serviceName + `",` +
			`http_target="` + path + `"}`)
		require.NoError(t, err)
		// check duration_count has 3 calls and all the arguments
		require.Len(t, results, 1)
		assert.Equal(t, 3, totalPromCount(t, results))
	}, test.Interval(1000*time.Millisecond))

}

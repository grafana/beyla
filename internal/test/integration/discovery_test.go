//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/require"

	ti "go.opentelemetry.io/obi/pkg/test/integration"

	"github.com/grafana/beyla/v2/internal/test/integration/components/docker"
	"github.com/grafana/beyla/v2/internal/test/integration/components/jaeger"
	"github.com/grafana/beyla/v2/internal/test/integration/components/prom"
)

func testSelectiveExports(t *testing.T) {
	waitForTestComponents(t, "http://localhost:5003")

	getTraces := func(service string, path string) []jaeger.Trace {
		query := "http://localhost:16686/api/traces?service=" + service
		resp, err := http.Get(query)
		require.NoError(t, err)

		if resp == nil {
			return nil
		}

		require.Equal(t, http.StatusOK, resp.StatusCode)

		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))

		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: path})

		return traces
	}

	// give enough time for the NodeJS injector to finish
	// TODO: once we implement the instrumentation status query API, replace
	// this with  a proper check to see if the target process has finished
	// being instrumented
	test.Eventually(t, 3*time.Minute, func(t require.TestingT) {
		ti.DoHTTPGet(t, "http://localhost:5001/b", 200)
		bTraces := getTraces("service-b", "/b")
		require.NotNil(t, bTraces)
	})

	// Run couple of requests to make sure we flush out any transactions that might be
	// stuck because of our tracking of full request times
	for i := 0; i < 10; i++ {
		ti.DoHTTPGet(t, "http://localhost:5000/a", 200)
		ti.DoHTTPGet(t, "http://localhost:5001/b", 200)
	}

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		aTraces := getTraces("service-a", "/a")
		bTraces := getTraces("service-b", "/b")
		cTraces := getTraces("service-c", "/c")
		dTraces := getTraces("service-d", "/d")

		require.Empty(t, aTraces)
		require.NotEmpty(t, bTraces)
		require.NotEmpty(t, cTraces)
		require.NotEmpty(t, dTraces)
	}, test.Interval(500*time.Millisecond))

	pq := prom.Client{HostPort: "localhost:9090"}

	getMetrics := func(path string) []prom.Result {
		query := fmt.Sprintf(`http_server_request_duration_seconds_count{url_path="%s"}`, path)
		results, err := pq.Query(query)

		require.NoError(t, err)

		return results
	}

	test.Eventually(t, 10*time.Second, func(t require.TestingT) {
		require.NotEmpty(t, getMetrics("/a"))
	})

	bMetrics := getMetrics("/b")
	cMetrics := getMetrics("/c")
	dMetrics := getMetrics("/d")

	require.NotEmpty(t, bMetrics)
	require.Empty(t, cMetrics)
	require.NotEmpty(t, dMetrics)
}

func TestDiscoverySection(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-discovery.yml", path.Join(pathOutput, "test-suite-discovery.log"))
	require.NoError(t, err)

	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `BEYLA_EXECUTABLE_PATH=`, `BEYLA_OPEN_PORT=`)
	require.NoError(t, compose.Up())

	t.Run("Selective exports", testSelectiveExports)

	require.NoError(t, compose.Close())
}

//go:build integration

package integration

import (
	"net"
	"path"
	"testing"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/test/integration/components/docker"
	"github.com/grafana/beyla/test/integration/components/prom"
)

func testREDMetricsForHTTP2Library(t *testing.T, route, svcNs string) {
	// Eventually, Prometheus would make this query visible
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="` + svcNs + `",` +
			`service_name="server",` +
			`http_route="` + route + `",` +
			`url_path="` + route + `"}`)
		require.NoError(t, err)
		// check duration_count has 3 calls and all the arguments
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 1, val)
		if len(results) > 0 {
			res := results[0]
			addr := net.ParseIP(res.Metric["client_address"])
			assert.NotNil(t, addr)
		}
	})

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_size_bytes_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="` + svcNs + `",` +
			`service_name="server",` +
			`http_route="` + route + `",` +
			`url_path="` + route + `"}`)
		require.NoError(t, err)
		// check duration_count has 3 calls and all the arguments
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 3, val)
		if len(results) > 0 {
			res := results[0]
			addr := net.ParseIP(res.Metric["client_address"])
			assert.NotNil(t, addr)
		}
	})

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_client_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="` + svcNs + `",` +
			`service_name="client"}`)
		require.NoError(t, err)
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 1, val)
	})

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_client_request_size_bytes_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="` + svcNs + `",` +
			`service_name="client"}`)
		require.NoError(t, err)
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 1, val)
	})
}

func TestHTTP2Go(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-http2.yml", path.Join(pathOutput, "test-suite-http2.log"))
	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `BEYLA_EXECUTABLE_NAME=`, `BEYLA_OPEN_PORT=`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	t.Run("Go RED metrics: usual service", func(t *testing.T) {
		testREDMetricsForHTTP2Library(t, "/ping", "http2-go")
		testREDMetricsForHTTP2Library(t, "/pingdo", "http2-go")
		testREDMetricsForHTTP2Library(t, "/pingrt", "http2-go")
	})

	t.Run("BPF pinning folders mounted", func(t *testing.T) {
		// 1 beyla pinned map folder for all processes
		testBPFPinningMounted(t)
	})

	require.NoError(t, compose.Close())
	t.Run("BPF pinning folder unmounted", testBPFPinningUnmounted)
}

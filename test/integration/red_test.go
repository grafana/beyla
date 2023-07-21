//go:build integration

package integration

import (
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/ebpf-autoinstrument/test/integration/components/prom"
	grpcclient "github.com/grafana/ebpf-autoinstrument/test/integration/components/testserver/grpc/client"
)

const (
	instrumentedServiceStdURL        = "http://localhost:8080"
	instrumentedServiceGinURL        = "http://localhost:8081"
	instrumentedServiceGorillaURL    = "http://localhost:8082"
	instrumentedServiceGorillaMidURL = "http://localhost:8083"
	prometheusHostPort               = "localhost:9090"
	jaegerQueryURL                   = "http://localhost:16686/api/traces"

	testTimeout = 20 * time.Second
)

func rndStr() string {
	return strconv.Itoa(rand.Intn(10000))
}

func waitForTestComponents(t *testing.T, url string) {
	waitForTestComponentsSub(t, url, "/smoke")
}

func testREDMetricsHTTP(t *testing.T) {
	for _, testCaseURL := range []string{
		instrumentedServiceStdURL,
		instrumentedServiceGorillaURL,
		instrumentedServiceGinURL,
		instrumentedServiceGorillaMidURL,
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponents(t, testCaseURL)
			testREDMetricsForHTTPLibrary(t, testCaseURL)
		})
	}
}

func testREDMetricsForHTTPLibrary(t *testing.T, url string) {
	path := "/basic/" + rndStr()

	// Call 3 times the instrumented service, forcing it to:
	// - take at least 30ms to respond
	// - returning a 404 code
	for i := 0; i < 3; i++ {
		doHTTPGet(t, url+path+"?delay=30ms&status=404", 404)
		if url == instrumentedServiceGorillaURL {
			doHTTPGet(t, url+"/echo", 203)
			doHTTPGet(t, url+"/echoCall", 204)
		}
	}

	// Eventually, Prometheus would make this query visible
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_duration_seconds_count{` +
			`http_method="GET",` +
			`http_status_code="404",` +
			`service_namespace="integration-test",` +
			`service_name="testserver",` +
			`http_route="/basic/:rnd",` +
			`http_target="` + path + `"}`)
		require.NoError(t, err)
		// check duration_count has 3 calls and all the arguments
		require.Len(t, results, 1)
		res := results[0]
		require.Len(t, res.Value, 2)
		assert.Equal(t, "3", res.Value[1])
		addr := net.ParseIP(res.Metric["net_sock_peer_addr"])
		assert.NotNil(t, addr)
	})

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_size_bytes_count{` +
			`http_method="GET",` +
			`http_status_code="404",` +
			`service_namespace="integration-test",` +
			`service_name="testserver",` +
			`http_route="/basic/:rnd",` +
			`http_target="` + path + `"}`)
		require.NoError(t, err)
		// check duration_count has 3 calls and all the arguments
		require.Len(t, results, 1)
		res := results[0]
		require.Len(t, res.Value, 2)
		assert.Equal(t, "3", res.Value[1])
		addr := net.ParseIP(res.Metric["net_sock_peer_addr"])
		assert.NotNil(t, addr)
	})

	if url == instrumentedServiceGorillaURL {
		test.Eventually(t, testTimeout, func(t require.TestingT) {
			var err error
			results, err = pq.Query(`http_client_duration_seconds_count{` +
				`http_method="GET",` +
				`http_status_code="203",` +
				`service_namespace="integration-test",` +
				`service_name="testserver"}`)
			require.NoError(t, err)
			// check duration_count has 3 calls
			require.Len(t, results, 1)
			res := results[0]
			require.Len(t, res.Value, 2)
			assert.Equal(t, "3", res.Value[1])
		})

		test.Eventually(t, testTimeout, func(t require.TestingT) {
			var err error
			results, err = pq.Query(`http_client_request_size_bytes_count{` +
				`http_method="GET",` +
				`http_status_code="203",` +
				`service_namespace="integration-test",` +
				`service_name="testserver"}`)
			require.NoError(t, err)
			// check duration_count has 3 calls
			require.Len(t, results, 1)
			res := results[0]
			require.Len(t, res.Value, 2)
			assert.Equal(t, "3", res.Value[1])
		})

		test.Eventually(t, testTimeout, func(t require.TestingT) {
			var err error
			results, err = pq.Query(`rpc_client_duration_seconds_count{` +
				`rpc_grpc_status_code="0",` +
				`service_name="testserver",` +
				`service_namespace="integration-test",` +
				`rpc_method="/routeguide.RouteGuide/GetFeature"}`)
			require.NoError(t, err)
			// check duration_count has at least 3 calls
			require.Len(t, results, 1)
			res := results[0]
			require.Len(t, res.Value, 2)
			assert.LessOrEqual(t, "3", res.Value[1])
		})
	}

	// check duration_sum is at least 90ms (3 * 30ms)
	var err error
	results, err = pq.Query(`http_server_duration_seconds_sum{` +
		`http_method="GET",` +
		`http_status_code="404",` +
		`service_name="testserver",` +
		`service_namespace="integration-test",` +
		`http_route="/basic/:rnd",` +
		`http_target="` + path + `"}`)
	require.NoError(t, err)
	require.Len(t, results, 1)
	res := results[0]
	require.Len(t, res.Value, 2)
	sum, err := strconv.ParseFloat(fmt.Sprint(res.Value[1]), 64)
	require.NoError(t, err)
	assert.Less(t, sum, 1.0)
	assert.Greater(t, sum, (90 * time.Millisecond).Seconds())
	addr := net.ParseIP(res.Metric["net_sock_peer_addr"])
	assert.NotNil(t, addr)

	// check request_size_sum is at least 114B (3 * 38B)
	results, err = pq.Query(`http_server_request_size_bytes_sum{` +
		`http_method="GET",` +
		`http_status_code="404",` +
		`service_name="testserver",` +
		`service_namespace="integration-test",` +
		`http_route="/basic/:rnd",` +
		`http_target="` + path + `"}`)
	require.NoError(t, err)
	require.Len(t, results, 1)
	res = results[0]
	require.Len(t, res.Value, 2)
	sum, err = strconv.ParseFloat(fmt.Sprint(res.Value[1]), 64)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, sum, 114.0)
	addr = net.ParseIP(res.Metric["net_sock_peer_addr"])
	assert.NotNil(t, addr)
}

func testREDMetricsGRPC(t *testing.T) {
	// Call 300 times the instrumented service, an overkill to make sure
	// we get some of the metrics to be visible in Prometheus. This test is
	// currently the last one that runs.
	for i := 0; i < 300; i++ {
		err := grpcclient.Ping()
		require.NoError(t, err)
	}

	// Eventually, Prometheus would make this query visible
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`rpc_server_duration_seconds_count{` +
			`rpc_grpc_status_code="0",` +
			`service_namespace="integration-test",` +
			`net_sock_peer_addr!="127.0.0.1",` + // discard the metrics from testREDMetricsForHTTPLibrary/GorillaURL
			`service_name="testserver",` +
			`rpc_method="/routeguide.RouteGuide/GetFeature"}`)
		require.NoError(t, err)
		// check duration_count has at least 3 calls and all the arguments
		require.Len(t, results, 1)
		res := results[0]
		require.Len(t, res.Value, 2)
		assert.LessOrEqual(t, "3", res.Value[1])
		addr := net.ParseIP(res.Metric["net_sock_peer_addr"])
		assert.NotNil(t, addr)
	})
}

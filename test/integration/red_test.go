//go:build integration

package integration

import (
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/grafana/ebpf-autoinstrument/test/integration/components/prom"
	grpcclient "github.com/grafana/ebpf-autoinstrument/test/integration/components/testserver/grpc/client"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	instrumentedServiceStdURL     = "http://localhost:8080"
	instrumentedServiceGinURL     = "http://localhost:8081"
	instrumentedServiceGorillaURL = "http://localhost:8082"
	prometheusHostPort            = "localhost:9090"

	testTimeout = 5 * time.Second
)

func rndStr() string {
	return strconv.Itoa(rand.Intn(10000))
}

// does a smoke test to verify that all the components that started
// asynchronously are up and communicating properly
func waitForTestComponents(t *testing.T, url string) {
	pq := prom.Client{HostPort: prometheusHostPort}
	test.Eventually(t, time.Minute, func(t require.TestingT) {
		// first, verify that the test service endpoint is healthy
		r, err := http.Get(url + "/smoke")
		require.NoError(t, err)
		if r == nil {
			return
		}
		require.Equal(t, http.StatusOK, r.StatusCode)

		// now, verify that the metric has been reported.
		// we don't really care that this metric could be from a previous
		// test. Once one it is visible, it means that Otel and Prometheus are healthy
		results, err := pq.Query(`http_server_duration_count{http_target="/smoke"}`)
		require.NoError(t, err)
		require.NotZero(t, len(results))
	}, test.Interval(time.Second))
}

func testREDMetricsHTTP(t *testing.T) {
	for _, testCaseURL := range []string{
		instrumentedServiceStdURL,
		instrumentedServiceGorillaURL,
		instrumentedServiceGinURL,
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponents(t, testCaseURL)
			testREDMetricsForHTTPLibrary(t, testCaseURL)
		})
	}
}

func doHTTPGet(t *testing.T, path string, status int) {
	// Random fake body to cause the request to have some size (38 bytes)
	jsonBody := []byte(`{"productId": 123456, "quantity": 100}`)

	req, err := http.NewRequest(http.MethodGet, path, bytes.NewReader(jsonBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	r, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, status, r.StatusCode)
	time.Sleep(300 * time.Millisecond)
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
		results, err = pq.Query(`http_server_duration_count{` +
			`http_method="GET",` +
			`http_status_code="404",` +
			`service_name="testserver",` +
			`http_route="/basic/:rnd",` +
			`http_target="` + path + `"}`)
		require.NoError(t, err)
		// check duration_count has 3 calls and all the arguments
		require.Len(t, results, 1)
		if len(results) > 0 {
			res := results[0]
			require.Len(t, res.Value, 2)
			assert.Equal(t, "3", res.Value[1])
			addr := net.ParseIP(res.Metric["net_sock_peer_addr"])
			assert.NotNil(t, addr)
		}
	})

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_size_count{` +
			`http_method="GET",` +
			`http_status_code="404",` +
			`service_name="testserver",` +
			`http_route="/basic/:rnd",` +
			`http_target="` + path + `"}`)
		require.NoError(t, err)
		// check duration_count has 3 calls and all the arguments
		require.Len(t, results, 1)
		if len(results) > 0 {
			res := results[0]
			require.Len(t, res.Value, 2)
			assert.Equal(t, "3", res.Value[1])
			addr := net.ParseIP(res.Metric["net_sock_peer_addr"])
			assert.NotNil(t, addr)
		}
	})

	if url == instrumentedServiceGorillaURL {
		test.Eventually(t, testTimeout, func(t require.TestingT) {
			var err error
			results, err = pq.Query(`http_client_duration_count{` +
				`http_method="GET",` +
				`http_status_code="203",` +
				`service_name="testserver"}`)
			require.NoError(t, err)
			// check duration_count has 3 calls
			require.Len(t, results, 1)
			if len(results) > 0 {
				res := results[0]
				require.Len(t, res.Value, 2)
				assert.Equal(t, "3", res.Value[1])
			}
		})

		test.Eventually(t, testTimeout, func(t require.TestingT) {
			var err error
			results, err = pq.Query(`http_client_request_size_count{` +
				`http_method="GET",` +
				`http_status_code="203",` +
				`service_name="testserver"}`)
			require.NoError(t, err)
			// check duration_count has 3 calls
			require.Len(t, results, 1)
			if len(results) > 0 {
				res := results[0]
				require.Len(t, res.Value, 2)
				assert.Equal(t, "3", res.Value[1])
			}
		})

		test.Eventually(t, testTimeout, func(t require.TestingT) {
			var err error
			results, err = pq.Query(`rpc_client_duration_count{` +
				`rpc_grpc_status_code="0",` +
				`service_name="testserver",` +
				`rpc_method="/routeguide.RouteGuide/GetFeature"}`)
			require.NoError(t, err)
			// check duration_count has at least 3 calls
			require.Len(t, results, 1)
			if len(results) > 0 {
				res := results[0]
				require.Len(t, res.Value, 2)
				assert.LessOrEqual(t, "3", res.Value[1])
			}
		})
	}

	// check duration_sum is at least 90ms (3 * 30ms)
	var err error
	results, err = pq.Query(`http_server_duration_sum{` +
		`http_method="GET",` +
		`http_status_code="404",` +
		`service_name="testserver",` +
		`http_route="/basic/:rnd",` +
		`http_target="` + path + `"}`)
	require.NoError(t, err)
	require.Len(t, results, 1)
	res := results[0]
	require.Len(t, res.Value, 2)
	sum, err := strconv.ParseFloat(fmt.Sprint(res.Value[1]), 64)
	require.NoError(t, err)
	assert.Greater(t, sum, 90.0)
	addr := net.ParseIP(res.Metric["net_sock_peer_addr"])
	assert.NotNil(t, addr)

	// check request_size_sum is at least 114B (3 * 38B)
	results, err = pq.Query(`http_server_request_size_sum{` +
		`http_method="GET",` +
		`http_status_code="404",` +
		`service_name="testserver",` +
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
		results, err = pq.Query(`rpc_server_duration_count{` +
			`rpc_grpc_status_code="0",` +
			`service_name="testserver",` +
			`rpc_method="/routeguide.RouteGuide/GetFeature"}`)
		require.NoError(t, err)
		// check duration_count has at least 3 calls and all the arguments
		require.Len(t, results, 1)
		if len(results) > 0 {
			res := results[0]
			require.Len(t, res.Value, 2)
			assert.LessOrEqual(t, "3", res.Value[1])
			addr := net.ParseIP(res.Metric["net_sock_peer_addr"])
			assert.NotNil(t, addr)
		}
	})
}

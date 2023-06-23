//go:build integration

package integration

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
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
	instrumentedServiceStdURL     = "http://localhost:8080"
	instrumentedServiceGinURL     = "http://localhost:8081"
	instrumentedServiceGorillaURL = "http://localhost:8082"
	prometheusHostPort            = "localhost:9090"
	jaegerQueryURL                = "http://localhost:16686/api/traces"

	testTimeout = 10 * time.Second
)

var tr = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}
var httpClient = &http.Client{Transport: tr}

func rndStr() string {
	return strconv.Itoa(rand.Intn(10000))
}

// does a smoke test to verify that all the components that started
// asynchronously are up and communicating properly
func waitForTestComponents(t *testing.T, url string) {
	pq := prom.Client{HostPort: prometheusHostPort}
	test.Eventually(t, time.Minute, func(t require.TestingT) {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest("GET", url+"/smoke", nil)
		require.NoError(t, err)
		r, err := httpClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode)

		// now, verify that the metric has been reported.
		// we don't really care that this metric could be from a previous
		// test. Once one it is visible, it means that Otel and Prometheus are healthy
		results, err := pq.Query(`http_server_duration_seconds_count{http_target="/smoke"}`)
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

// does a smoke test to verify that all the components that started
// asynchronously for the Java test are up and communicating properly
func waitForJavaTestComponents(t *testing.T, url string) {
	pq := prom.Client{HostPort: prometheusHostPort}
	test.Eventually(t, time.Minute, func(t require.TestingT) {
		// first, verify that the test service endpoint is healthy
		r, err := http.Get(url + "/greeting")
		require.NoError(t, err)
		if r == nil {
			return
		}
		require.Equal(t, http.StatusOK, r.StatusCode)

		// now, verify that the metric has been reported.
		// we don't really care that this metric could be from a previous
		// test. Once one it is visible, it means that Otel and Prometheus are healthy
		results, err := pq.Query(`http_server_duration_seconds_count{http_target="/greeting"}`)
		require.NoError(t, err)
		require.NotZero(t, len(results))
	}, test.Interval(time.Second))
}

func testREDMetricsForJavaHTTPLibrary(t *testing.T, url string, comm string, systemWide bool) {
	path := "/greeting"

	// Call 3 times the instrumented service, forcing it to:
	// - take at least 30ms to respond
	// - returning a 204 code
	for i := 0; i < 4; i++ {
		doHTTPGet(t, url+path+"?delay=30&response=204", 204)
	}

	// Eventually, Prometheus would make this query visible
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_duration_seconds_count{` +
			`http_method="GET",` +
			`http_status_code="204",` +
			`service_namespace="integration-test",` +
			`service_name="` + comm + `",` +
			`http_target="` + path + `"}`)
		require.NoError(t, err)
		// check duration_count has 3 calls and all the arguments
		if systemWide {
			assert.LessOrEqual(t, 1, len(results))
		} else {
			require.Len(t, results, 1)
		}
		if len(results) > 0 {
			res := results[0]
			require.Len(t, res.Value, 2)
			assert.LessOrEqual(t, "3", res.Value[1])
			addr := net.ParseIP(res.Metric["net_sock_peer_addr"])
			assert.NotNil(t, addr)
		}
	})
}

func testREDMetricsJavaHTTP(t *testing.T) {
	for _, testCaseURL := range []string{
		"http://localhost:8086",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForJavaTestComponents(t, testCaseURL)
			testREDMetricsForJavaHTTPLibrary(t, testCaseURL, "greeting", false)
		})
	}
}

func testREDMetricsJavaHTTPSystemWide(t *testing.T) {
	for _, testCaseURL := range []string{
		"http://localhost:8086",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForJavaTestComponents(t, testCaseURL)
			testREDMetricsForJavaHTTPLibrary(t, testCaseURL, "", true)
		})
	}
}

func doHTTPPost(t *testing.T, path string, status int) {
	// Random fake body to cause the request to have some size (38 bytes)
	jsonBody := []byte(`{"name": "Someone", "number": 123}`)

	req, err := http.NewRequest(http.MethodPost, path, bytes.NewReader(jsonBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	r, err := httpClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, status, r.StatusCode)
	time.Sleep(300 * time.Millisecond)
}

func testREDMetricsForRustHTTPLibrary(t *testing.T, url string, comm string) {
	path := "/greeting"

	// Call 3 times the instrumented service, forcing it to:
	// - take at least 30ms to respond
	// - returning a 204 code
	for i := 0; i < 4; i++ {
		doHTTPPost(t, url+path, 200)
	}

	// Eventually, Prometheus would make this query visible
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_duration_seconds_count{` +
			`http_method="POST",` +
			`http_status_code="200",` +
			`service_namespace="integration-test",` +
			`service_name="` + comm + `",` +
			`http_target="` + path + `"}`)
		require.NoError(t, err)
		require.Len(t, results, 1)
		res := results[0]
		require.Len(t, res.Value, 2)
		assert.LessOrEqual(t, "3", res.Value[1])
		addr := net.ParseIP(res.Metric["net_sock_peer_addr"])
		assert.NotNil(t, addr)
	})
}

func testREDMetricsRustHTTP(t *testing.T) {
	for _, testCaseURL := range []string{
		"http://localhost:8091",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponents(t, testCaseURL)
			testREDMetricsForRustHTTPLibrary(t, testCaseURL, "greetings")
		})
	}
}

func testREDMetricsRustHTTPS(t *testing.T) {
	for _, testCaseURL := range []string{
		"https://localhost:8491",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponents(t, testCaseURL)
			testREDMetricsForRustHTTPLibrary(t, testCaseURL, "greetings")
		})
	}
}

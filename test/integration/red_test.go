//go:build integration

package integration

import (
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v2/test/integration/components/prom"
	grpcclient "github.com/grafana/beyla/v2/test/integration/components/testserver/grpc/client"
)

const (
	instrumentedServiceStdURL         = "http://localhost:8080"
	instrumentedServiceGinURL         = "http://localhost:8081"
	instrumentedServiceGorillaURL     = "http://localhost:8082"
	instrumentedServiceGorillaMidURL  = "http://localhost:8083"
	instrumentedServiceGorillaMid2URL = "http://localhost:8087"
	instrumentedServiceStdTLSURL      = "https://localhost:8383"
	prometheusHostPort                = "localhost:9090"
	jaegerQueryURL                    = "http://localhost:16686/api/traces"

	testTimeout = 60 * time.Second
)

func rndStr() string {
	return strconv.Itoa(rand.Intn(10000))
}

func waitForTestComponents(t *testing.T, url string) {
	waitForTestComponentsSub(t, url, "/smoke")
}

func waitForTestComponentsHTTP2(t *testing.T, url string) {
	waitForTestComponentsHTTP2Sub(t, url, "/smoke", 1)
}

func testREDMetricsHTTP(t *testing.T) {
	for _, testCaseURL := range []string{
		instrumentedServiceStdURL,
		instrumentedServiceGorillaURL,
		instrumentedServiceGinURL,
		instrumentedServiceGorillaMidURL,
		instrumentedServiceGorillaMid2URL,
		instrumentedServiceStdTLSURL,
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponents(t, testCaseURL)
			testREDMetricsForHTTPLibrary(t, testCaseURL, "testserver", "integration-test")
			testSpanMetricsForHTTPLibrary(t, "testserver", "integration-test")
			testServiceGraphMetricsForHTTPLibrary(t, "integration-test")
		})
	}
}

// this needs to be removed once we figure out why Gorilla async didn't work.
func testREDMetricsOldHTTP(t *testing.T) {
	for _, testCaseURL := range []string{
		instrumentedServiceStdURL,
		instrumentedServiceGinURL,
		instrumentedServiceGorillaMidURL,
		instrumentedServiceGorillaMid2URL,
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponents(t, testCaseURL)
			testREDMetricsForHTTPLibrary(t, testCaseURL, "testserver", "integration-test")
			testSpanMetricsForHTTPLibrary(t, "testserver", "integration-test")
		})
	}
}

// this needs to be removed once we figure out why Gorilla async didn't work.
func testREDMetricsShortHTTP(t *testing.T) {
	for _, testCaseURL := range []string{
		instrumentedServiceStdURL,
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponents(t, testCaseURL)
			testREDMetricsForHTTPLibrary(t, testCaseURL, "testserver", "integration-test")
			testSpanMetricsForHTTPLibrary(t, "testserver", "integration-test")
		})
	}
}

func testExemplarsExist(t *testing.T) {
	url := "http://" + prometheusHostPort + "/api/v1/query_exemplars?query=http_server_request_duration_seconds_bucket"

	var qtr = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	var qClient = &http.Client{Transport: qtr}

	req, err := http.NewRequest("GET", url, nil)
	require.NoError(t, err)
	r, err := qClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, r.StatusCode)

	// Read the response body
	body, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	defer r.Body.Close()

	// Convert the body to a string
	bodyStr := string(body)

	assert.Contains(t, bodyStr, "exemplars", "The response body does not contain exemplars")
}

// **IMPORTANT** Tests must first call -> func testREDMetricsForHTTPLibrary(t *testing.T, url, svcName, svcNs string) {
func testSpanMetricsForHTTPLibrary(t *testing.T, svcName, svcNs string) {
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result

	// Test span metrics
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`traces_spanmetrics_latency_count{` +
			`span_kind="SPAN_KIND_SERVER",` +
			`status_code="0",` + // 404 is OK for server spans
			`service_namespace="` + svcNs + `",` +
			`service="` + svcName + `",` +
			`span_name="GET /basic/:rnd"` +
			`}`)
		require.NoError(t, err)
		// check span metric latency exists
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 3, val)
	})

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`traces_spanmetrics_calls_total{` +
			`span_kind="SPAN_KIND_SERVER",` +
			`status_code="0",` + // 404 is OK for server spans
			`service_namespace="` + svcNs + `",` +
			`service="` + svcName + `",` +
			`span_name="GET /basic/:rnd"` +
			`}`)
		require.NoError(t, err)
		// check calls total exists
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 3, val)
	})

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`traces_target_info{` +
			`service_namespace="` + svcNs + `",` +
			`service="` + svcName + `",` +
			`telemetry_sdk_language="go"` +
			`}`)
		require.NoError(t, err)
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 1, val) // we report this count for each service, doesn't matter how many calls
	})
}

// **IMPORTANT** Tests must first call -> func testREDMetricsForHTTPLibrary(t *testing.T, url, svcName, svcNs string) {
func testServiceGraphMetricsForHTTPLibrary(t *testing.T, svcNs string) {
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result

	// Test span metrics
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`traces_service_graph_request_server_seconds_count{` +
			`service_namespace="` + svcNs + `"` +
			`} or traces_service_graph_request_server_seconds_count{` +
			`server_service_namespace="` + svcNs + `"}`)
		require.NoError(t, err)
		// check span metric latency exists
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 3, val)
	})

	var err error
	results, err = pq.Query(`traces_service_graph_request_server_seconds_count{` +
		`client="127.0.0.1",` +
		`server="127.0.0.1"` +
		`}`)
	require.NoError(t, err)
	// check calls total to 0, no self references
	val := totalPromCount(t, results)
	assert.Equal(t, 0, val)

	results, err = pq.Query(`traces_service_graph_request_server_seconds_count{` +
		`client="::1",` +
		`server="::1"` +
		`}`)
	require.NoError(t, err)
	// check calls total to 0, no self references
	val = totalPromCount(t, results)
	assert.Equal(t, 0, val)
}

func testREDMetricsForHTTPLibrary(t *testing.T, url, svcName, svcNs string) {
	path := "/basic/" + rndStr()

	parts := strings.Split(url, ":")
	assert.LessOrEqual(t, 3, len(parts))

	lastPart := parts[len(parts)-1]
	parts = strings.Split(lastPart, "/")
	serverPort := parts[0]

	// Call 3 times the instrumented service, forcing it to:
	// - take at least 30ms to respond
	// - returning a 404 code
	for i := 0; i < 4; i++ {
		doHTTPGet(t, url+"/metrics", 200)
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
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="404",` +
			`service_namespace="` + svcNs + `",` +
			`service_name="` + svcName + `",` +
			`server_port="` + serverPort + `",` +
			`http_route="/basic/:rnd",` +
			`url_path="` + path + `"}`)
		require.NoError(t, err)
		// check duration_count has 3 calls and all the arguments
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 3, val)
		if len(results) > 0 {
			res := results[0]
			addr := res.Metric["client_address"]
			assert.NotNil(t, addr)
			assert.NotNil(t, res.Metric["server_port"])
		}
	})

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_body_size_bytes_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="404",` +
			`service_namespace="` + svcNs + `",` +
			`service_name="` + svcName + `",` +
			`http_route="/basic/:rnd",` +
			`url_path="` + path + `"}`)
		require.NoError(t, err)
		// check duration_count has 3 calls and all the arguments
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 3, val)
		if len(results) > 0 {
			res := results[0]
			addr := res.Metric["client_address"]
			assert.NotNil(t, addr)
		}
	})

	if url == instrumentedServiceGorillaURL {
		// Make sure we see /echo
		test.Eventually(t, testTimeout, func(t require.TestingT) {
			var err error
			results, err = pq.Query(`http_server_request_duration_seconds_count{` +
				`http_request_method="GET",` +
				`http_response_status_code="203",` +
				`service_namespace="` + svcNs + `",` +
				`http_route="/echo",` +
				`service_name="` + svcName + `"}`)
			require.NoError(t, err)
			// check duration_count has 3 calls
			enoughPromResults(t, results)
			val := totalPromCount(t, results)
			assert.LessOrEqual(t, 3, val)
		})

		test.Eventually(t, testTimeout, func(t require.TestingT) {
			var err error
			results, err = pq.Query(`http_server_request_body_size_bytes_count{` +
				`http_request_method="GET",` +
				`http_response_status_code="203",` +
				`service_namespace="` + svcNs + `",` +
				`http_route="/echo",` +
				`service_name="` + svcName + `"}`)
			require.NoError(t, err)
			// check duration_count has 3 calls
			enoughPromResults(t, results)
			val := totalPromCount(t, results)
			assert.LessOrEqual(t, 3, val)
		})

		// Make sure we see /echoBack server
		test.Eventually(t, testTimeout, func(t require.TestingT) {
			var err error
			results, err = pq.Query(`http_server_request_duration_seconds_count{` +
				`http_request_method="GET",` +
				`http_response_status_code="203",` +
				`service_namespace="` + svcNs + `",` +
				`http_route="/echoBack",` +
				`service_name="` + svcName + `"}`)
			require.NoError(t, err)
			// check duration_count has 3 calls
			enoughPromResults(t, results)
			val := totalPromCount(t, results)
			assert.LessOrEqual(t, 3, val)
		})

		test.Eventually(t, testTimeout, func(t require.TestingT) {
			var err error
			results, err = pq.Query(`http_server_request_body_size_bytes_count{` +
				`http_request_method="GET",` +
				`http_response_status_code="203",` +
				`service_namespace="` + svcNs + `",` +
				`http_route="/echoBack",` +
				`service_name="` + svcName + `"}`)
			require.NoError(t, err)
			// check duration_count has 3 calls
			enoughPromResults(t, results)
			val := totalPromCount(t, results)
			assert.LessOrEqual(t, 3, val)
		})

		// make sure we see /echo client
		test.Eventually(t, testTimeout, func(t require.TestingT) {
			var err error
			results, err = pq.Query(`http_client_request_duration_seconds_count{` +
				`http_request_method="GET",` +
				`http_response_status_code="203",` +
				`service_namespace="` + svcNs + `",` +
				`service_name="` + svcName + `"}`)
			require.NoError(t, err)
			// check duration_count has 3 calls
			enoughPromResults(t, results)
			val := totalPromCount(t, results)
			assert.LessOrEqual(t, 3, val)
		})

		test.Eventually(t, testTimeout, func(t require.TestingT) {
			var err error
			results, err = pq.Query(`http_client_request_body_size_bytes_count{` +
				`http_request_method="GET",` +
				`http_response_status_code="203",` +
				`service_namespace="` + svcNs + `",` +
				`service_name="` + svcName + `"}`)
			require.NoError(t, err)
			// check duration_count has 3 calls
			enoughPromResults(t, results)
			val := totalPromCount(t, results)
			assert.LessOrEqual(t, 3, val)
		})

		test.Eventually(t, testTimeout, func(t require.TestingT) {
			var err error
			results, err = pq.Query(`rpc_client_duration_seconds_count{` +
				`rpc_grpc_status_code="0",` +
				`service_name="` + svcName + `",` +
				`service_namespace="` + svcNs + `",` +
				`rpc_method="/routeguide.RouteGuide/GetFeature"}`)
			require.NoError(t, err)
			// check duration_count has at least 3 calls
			enoughPromResults(t, results)
			val := totalPromCount(t, results)
			assert.LessOrEqual(t, 3, val)
		})
	}

	// check duration_sum is at least 90ms (3 * 30ms)
	var err error
	results, err = pq.Query(`http_server_request_duration_seconds_sum{` +
		`http_request_method="GET",` +
		`http_response_status_code="404",` +
		`service_name="` + svcName + `",` +
		`service_namespace="` + svcNs + `",` +
		`http_route="/basic/:rnd",` +
		`url_path="` + path + `"}`)
	require.NoError(t, err)
	enoughPromResults(t, results)
	res := results[0]
	require.Len(t, res.Value, 2)
	sum, err := strconv.ParseFloat(fmt.Sprint(res.Value[1]), 64)
	require.NoError(t, err)
	assert.Less(t, sum, 1.0)
	assert.Greater(t, sum, (90 * time.Millisecond).Seconds())
	addr := res.Metric["client_address"]
	assert.NotNil(t, addr)

	// check request_size_sum is at least 114B (3 * 38B)
	results, err = pq.Query(`http_server_request_body_size_bytes_sum{` +
		`http_request_method="GET",` +
		`http_response_status_code="404",` +
		`service_name="` + svcName + `",` +
		`service_namespace="` + svcNs + `",` +
		`http_route="/basic/:rnd",` +
		`url_path="` + path + `"}`)
	require.NoError(t, err)
	enoughPromResults(t, results)
	res = results[0]
	require.Len(t, res.Value, 2)
	sum, err = strconv.ParseFloat(fmt.Sprint(res.Value[1]), 64)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, sum, 114.0)
	addr = res.Metric["client_address"]
	assert.NotNil(t, addr)

	// Check that we never recorded metrics for /metrics, in the basic test only traces are ignored
	results, err = pq.Query(`http_server_request_duration_seconds_count{http_route="/metrics"}`)
	require.NoError(t, err)
	enoughPromResults(t, results)
}

func testREDMetricsGRPC(t *testing.T) {
	testREDMetricsGRPCInternal(t, nil, "5051")
}

func testREDMetricsGRPCTLS(t *testing.T) {
	testREDMetricsGRPCInternal(t, []grpcclient.PingOption{grpcclient.WithSSL(), grpcclient.WithServerAddr("localhost:50051")}, "50051")
}

func testREDMetricsGRPCInternal(t *testing.T, opts []grpcclient.PingOption, serverPort string) {
	// Call 300 times the instrumented service, an overkill to make sure
	// we get some of the metrics to be visible in Prometheus. This test is
	// currently the last one that runs.
	for i := 0; i < 300; i++ {
		err := grpcclient.Ping(opts...)
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
			`client_address!="127.0.0.1",` + // discard the metrics from testREDMetricsForHTTPLibrary/GorillaURL
			`service_name="testserver",` +
			`server_port="` + serverPort + `",` +
			`rpc_method="/routeguide.RouteGuide/GetFeature"}`)
		require.NoError(t, err)
		// check duration_count has at least 3 calls and all the arguments
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 3, val)
		if len(results) > 0 {
			res := results[0]
			addr := res.Metric["client_address"]
			assert.NotNil(t, addr)
			assert.NotNil(t, res.Metric["server_port"])
		}
	})
}

func testREDMetricsForHTTPLibraryNoRoute(t *testing.T, url, svcName string) {
	path := "/basic/" + rndStr()

	// Call 3 times the instrumented service, forcing it to:
	// - take at least 30ms to respond
	// - returning a 404 code
	for i := 0; i < 3; i++ {
		doHTTPGet(t, url+"/metrics", 200)
		doHTTPGet(t, url+path+"?delay=30ms&status=404", 404)
		doHTTPGet(t, url+"/echo", 203)
		doHTTPGet(t, url+"/echoCall", 204)
	}

	// Eventually, Prometheus would make this query visible
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="404",` +
			`service_namespace="integration-test",` +
			`service_name="` + svcName + `",` +
			`http_route="/basic/*",` +
			`url_path="` + path + `"}`)
		require.NoError(t, err)
		// check duration_count has 3 calls and all the arguments
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 3, val)
		if len(results) > 0 {
			res := results[0]
			addr := res.Metric["client_address"]
			assert.NotNil(t, addr)
		}
	})

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_body_size_bytes_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="404",` +
			`service_namespace="integration-test",` +
			`service_name="` + svcName + `",` +
			`http_route="/basic/*",` +
			`url_path="` + path + `"}`)
		require.NoError(t, err)
		// check duration_count has 3 calls and all the arguments
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 3, val)
		if len(results) > 0 {
			res := results[0]
			addr := res.Metric["client_address"]
			assert.NotNil(t, addr)
		}
	})

	// Make sure we see /echo
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="203",` +
			`service_namespace="integration-test",` +
			`http_route="/echo",` +
			`service_name="` + svcName + `"}`)
		require.NoError(t, err)
		// check duration_count has 3 calls
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 3, val)
	})

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_body_size_bytes_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="203",` +
			`service_namespace="integration-test",` +
			`http_route="/echo",` +
			`service_name="` + svcName + `"}`)
		require.NoError(t, err)
		// check duration_count has 3 calls
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 3, val)
	})

	// Make sure we see /echoBack server
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="203",` +
			`service_namespace="integration-test",` +
			`http_route="/echoBack",` +
			`service_name="` + svcName + `"}`)
		require.NoError(t, err)
		// check duration_count has 3 calls
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 3, val)
	})

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_body_size_bytes_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="203",` +
			`service_namespace="integration-test",` +
			`http_route="/echoBack",` +
			`service_name="` + svcName + `"}`)
		require.NoError(t, err)
		// check duration_count has 3 calls
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 3, val)
	})

	// make sure we see /echo client
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_client_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="203",` +
			`service_namespace="integration-test",` +
			`service_name="` + svcName + `"}`)
		require.NoError(t, err)
		// check duration_count has 3 calls
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 3, val)
	})

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_client_request_body_size_bytes_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="203",` +
			`service_namespace="integration-test",` +
			`service_name="` + svcName + `"}`)
		require.NoError(t, err)
		// check duration_count has 3 calls
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 3, val)
	})

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`rpc_client_duration_seconds_count{` +
			`rpc_grpc_status_code="0",` +
			`service_name="` + svcName + `",` +
			`service_namespace="integration-test",` +
			`rpc_method="/routeguide.RouteGuide/GetFeature"}`)
		require.NoError(t, err)
		// check duration_count has at least 3 calls
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 3, val)
	})

	// check duration_sum is at least 90ms (3 * 30ms)
	var err error
	results, err = pq.Query(`http_server_request_duration_seconds_sum{` +
		`http_request_method="GET",` +
		`http_response_status_code="404",` +
		`service_name="` + svcName + `",` +
		`service_namespace="integration-test",` +
		`http_route="/basic/*",` +
		`url_path="` + path + `"}`)
	require.NoError(t, err)
	enoughPromResults(t, results)
	res := results[0]
	require.Len(t, res.Value, 2)
	sum, err := strconv.ParseFloat(fmt.Sprint(res.Value[1]), 64)
	require.NoError(t, err)
	assert.Less(t, sum, 1.0)
	assert.Greater(t, sum, (90 * time.Millisecond).Seconds())
	addr := res.Metric["client_address"]
	assert.NotNil(t, addr)

	// check request_size_sum is at least 114B (3 * 38B)
	results, err = pq.Query(`http_server_request_body_size_bytes_sum{` +
		`http_request_method="GET",` +
		`http_response_status_code="404",` +
		`service_name="` + svcName + `",` +
		`service_namespace="integration-test",` +
		`http_route="/basic/*",` +
		`url_path="` + path + `"}`)
	require.NoError(t, err)
	enoughPromResults(t, results)
	res = results[0]
	require.Len(t, res.Value, 2)
	sum, err = strconv.ParseFloat(fmt.Sprint(res.Value[1]), 64)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, sum, 114.0)
	addr = res.Metric["client_address"]
	assert.NotNil(t, addr)

	// Check that we never recorded any /metrics calls
	results, err = pq.Query(`http_server_request_duration_seconds_count{http_route="/metrics"}`)
	require.NoError(t, err)
	require.Equal(t, len(results), 0)
}

func testREDMetricsHTTPNoRoute(t *testing.T) {
	for _, testCaseURL := range []string{
		instrumentedServiceGorillaURL,
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponents(t, testCaseURL)
			testREDMetricsForHTTPLibraryNoRoute(t, testCaseURL, "testserver")
		})
	}
}

func testREDMetricsUnsupportedHTTP(t *testing.T) {
	for _, testCaseURL := range []string{
		instrumentedServiceStdURL,
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponents(t, testCaseURL)
			testREDMetricsForGoBasicOnly(t, testCaseURL, "testserver")
		})
	}
}

func testREDMetricsForGoBasicOnly(t *testing.T, url string, comm string) {
	path := "/old"

	// Call 3 times the instrumented service, forcing it to:
	// - take at least 30ms to respond
	// - returning a 204 code
	for i := 0; i < 4; i++ {
		doHTTPGet(t, url+path+"?delay=30", 200)
	}

	commMatch := `service_name="` + comm + `",`
	namespaceMatch := `service_namespace="integration-test",`
	if comm == "" {
		commMatch = ""
		namespaceMatch = ""
	}

	// Eventually, Prometheus would make this query visible
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			namespaceMatch +
			commMatch +
			`url_path="` + path + `"}`)
		require.NoError(t, err)
		// check duration_count has 3 calls and all the arguments
		enoughPromResults(t, results)
		if len(results) > 0 {
			val := totalPromCount(t, results)
			assert.LessOrEqual(t, 3, val)

			res := results[0]
			addr := res.Metric["client_address"]
			assert.NotNil(t, addr)
		}
	})
}

func testPrometheusBeylaBuildInfo(t *testing.T) {
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`beyla_build_info{target_lang="go"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)
	})
}

func testHostInfo(t *testing.T) {
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`traces_host_info{}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)
	})
}

func testPrometheusBPFMetrics(t *testing.T) {
	t.Skip("BPF metrics are not available in the test environment")
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`bpf_probe_latency_seconds_count{probe_name=~"uprobe_.*"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)
	})

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`bpf_map_entries_total{map_name="ongoing_server_"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)
	})
}

func testPrometheusNoBeylaEvents(t *testing.T) {
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{service_name="beyla"}`)
		require.NoError(t, err)
		require.Equal(t, 0, len(results))
	})
}

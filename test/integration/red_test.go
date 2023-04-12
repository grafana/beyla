//go:build integration

package integration

import (
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
		results, err := pq.Query(`duration_count{http_target="/smoke"}`)
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

func testREDMetricsForHTTPLibrary(t *testing.T, url string) {
	path := "/basic/" + rndStr()

	// Call 3 times the instrumented service, forcing it to:
	// - take at least 30ms to respond
	// - returning a 404 code
	for i := 0; i < 3; i++ {
		r, err := http.Get(url + path + "?delay=30ms&status=404")
		require.NoError(t, err)
		require.Equal(t, 404, r.StatusCode)
		time.Sleep(300 * time.Millisecond)
	}

	// Eventually, Prometheus would make this query visible
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`duration_count{` +
			`http_method="GET",` +
			`http_status_code="404",` +
			`service_name="/testserver",` +
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

	// check duration_sum is at least 90ms (3 * 30ms)
	var err error
	results, err = pq.Query(`duration_sum{` +
		`http_method="GET",` +
		`http_status_code="404",` +
		`service_name="/testserver",` +
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
}

func testREDMetricsGRPC(t *testing.T) {
	// Call 3 times the instrumented service
	for i := 0; i < 3; i++ {
		err := grpcclient.Ping()
		require.NoError(t, err)
	}

	// Eventually, Prometheus would make this query visible
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`duration_count{` +
			`rpc_grpc_status_code="0",` +
			`service_name="/testserver",` +
			`rpc_method="/routeguide.RouteGuide/GetFeature"}`)
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
}

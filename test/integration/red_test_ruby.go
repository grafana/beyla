//go:build integration

package integration

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/ebpf-autoinstrument/test/integration/components/prom"
)

// does a smoke test to verify that all the components that started
// asynchronously for the Ruby test are up and communicating properly
func waitForRubyTestComponents(t *testing.T, url string) {
	waitForTestComponentsSub(t, url, "/users")
}

func testREDMetricsForRubyHTTPLibrary(t *testing.T, url string, comm string) {
	path := "/users"

	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result

	// add one record to users, it will get record id of 1
	jsonBody := []byte(`{"name": "Jane Doe", "email": "jane@grafana.com"}`)
	doHTTPPost(t, url+path, 201, jsonBody)

	// Eventually, Prometheus would make this query visible
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_duration_seconds_count{` +
			`http_method="POST",` +
			`http_status_code="201",` +
			`service_namespace="integration-test",` +
			`service_name="` + comm + `",` +
			`http_target="` + path + `"}`)
		require.NoError(t, err)
		require.Len(t, results, 1)
		if len(results) > 0 {
			res := results[0]
			require.Len(t, res.Value, 2)
			assert.LessOrEqual(t, "1", res.Value[1])
			addr := net.ParseIP(res.Metric["net_sock_peer_addr"])
			assert.NotNil(t, addr)
		}
	})

	// Call 10 times the instrumented service, forcing it to:
	// - SSL is very slow, it messes with our request timings, needs lots of calls
	// - returning a 200 code
	for i := 0; i < 10; i++ {
		doHTTPGet(t, url+path+"/1", 200)
		time.Sleep(2 * time.Millisecond)
	}

	// Eventually, Prometheus would make this query visible
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_duration_seconds_count{` +
			`http_method="GET",` +
			`http_status_code="200",` +
			`service_namespace="integration-test",` +
			`service_name="` + comm + `",` +
			`http_route="/users/:user_id",` +
			`http_target="` + path + `/1"}`)
		require.NoError(t, err)
		require.Len(t, results, 1)
		if len(results) > 0 {
			res := results[0]
			require.Len(t, res.Value, 2)
			val, err := strconv.Atoi(res.Value[1].(string))
			require.NoError(t, err)
			assert.LessOrEqual(t, 3, val)
			addr := net.ParseIP(res.Metric["net_sock_peer_addr"])
			assert.NotNil(t, addr)
		}
	})
}

func testREDMetricsRailsHTTP(t *testing.T) {
	for _, testCaseURL := range []string{
		"http://localhost:3041",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForRubyTestComponents(t, testCaseURL)
			testREDMetricsForRubyHTTPLibrary(t, testCaseURL, "ruby")
		})
	}
}

func testREDMetricsRailsHTTPS(t *testing.T) {
	for _, testCaseURL := range []string{
		"https://localhost:3041",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForRubyTestComponents(t, testCaseURL)
			testREDMetricsForRubyHTTPLibrary(t, testCaseURL, "ruby")
		})
	}
}

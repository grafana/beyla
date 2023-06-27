//go:build integration

package integration

import (
	"net"
	"testing"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/ebpf-autoinstrument/test/integration/components/prom"
)

// does a smoke test to verify that all the components that started
// asynchronously for the Java test are up and communicating properly
func waitForJavaTestComponents(t *testing.T, url string) {
	waitForTestComponentsSub(t, url, "/greeting")
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

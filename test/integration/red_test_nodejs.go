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

func testREDMetricsForNodeHTTPLibrary(t *testing.T, url string, comm string) {
	path := "/greeting"

	// Call 3 times the instrumented service, forcing it to:
	// - take at least 30ms to respond
	// - returning a 204 code
	for i := 0; i < 4; i++ {
		doHTTPGet(t, url+path, 200)
	}

	// Eventually, Prometheus would make this query visible
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_duration_seconds_count{` +
			`http_method="GET",` +
			`http_status_code="200",` +
			`service_namespace="integration-test",` +
			`service_name="` + comm + `",` +
			`http_target="` + path + `"}`)
		require.NoError(t, err)
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 3, val)
		if len(results) > 0 {
			res := results[0]
			addr := net.ParseIP(res.Metric["net_sock_peer_addr"])
			assert.NotNil(t, addr)
		}
	})
}

func testREDMetricsNodeJSHTTP(t *testing.T) {
	for _, testCaseURL := range []string{
		"http://localhost:3031",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponents(t, testCaseURL)
			testREDMetricsForNodeHTTPLibrary(t, testCaseURL, "node")
		})
	}
}

func testREDMetricsNodeJSHTTPS(t *testing.T) {
	for _, testCaseURL := range []string{
		"https://localhost:3034",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponents(t, testCaseURL)
			testREDMetricsForNodeHTTPLibrary(t, testCaseURL, "node")
		})
	}
}

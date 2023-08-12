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

func testREDMetricsForRustHTTPLibrary(t *testing.T, url string, comm string) {
	path := "/greeting"
	// Random fake body to cause the request to have some size (38 bytes)
	jsonBody := []byte(`{"name": "Someone", "number": 123}`)

	// Call 3 times the instrumented service, forcing it to:
	// - take at least 30ms to respond
	// - returning a 204 code
	for i := 0; i < 4; i++ {
		doHTTPPost(t, url+path, 200, jsonBody)
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
		require.GreaterOrEqual(t, len(results), 1)
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

//go:build integration

package integration

import (
	"testing"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ti "go.opentelemetry.io/obi/pkg/test/integration"

	"github.com/grafana/beyla/v2/internal/test/integration/components/prom"
	"github.com/grafana/beyla/v2/internal/test/tools"
)

func testREDMetricsForNetHTTPLibrary(t *testing.T, url string, comm string) {
	urlPath := "/greeting"

	// Call 3 times the instrumented service, forcing it to:
	// - take a large JSON file
	// - returning a 200 code
	for i := 0; i < 4; i++ {
		ti.DoHTTPGet(t, url+urlPath, 200)
	}

	// Eventually, Prometheus would make this query visible
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="integration-test",` +
			`service_name="` + comm + `",` +
			`url_path="` + urlPath + `"}`)
		require.NoError(t, err)
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 2, val, "received:", tools.ToJSON(val))
		if len(results) > 0 {
			res := results[0]
			addr := res.Metric["client_address"]
			assert.NotNil(t, addr)
		}
	})

	// Eventually, Prometheus would make this query visible
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_client_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="integration-test",` +
			`service_name="` + comm + `"}`)
		require.NoError(t, err)
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 2, val, "received:", tools.ToJSON(val))
	})
}

func testREDMetricsDotNetHTTP(t *testing.T) {
	for _, testCaseURL := range []string{
		"http://localhost:5267",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponents(t, testCaseURL)
			testREDMetricsForNetHTTPLibrary(t, testCaseURL, "dotnetserver") // reusing what we do for NodeJS
		})
	}
}

// Special test without checks for a peer address. With the async nature of SSL on .NET we can't always get
// this information
func testREDMetricsForNetHTTPSLibrary(t *testing.T, url string, comm string) {
	path := "/greeting"

	// Call 3 times the instrumented service, forcing it to:
	// - take at least 30ms to respond
	// - returning a 204 code
	for i := 0; i < 4; i++ {
		ti.DoHTTPGet(t, url+path, 200)
	}

	// Eventually, Prometheus would make this query visible
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="integration-test",` +
			`service_name="` + comm + `",` +
			`url_path="` + path + `"}`)
		require.NoError(t, err)
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 3, val)
	})
}

func testREDMetricsDotNetHTTPS(t *testing.T) {
	for _, testCaseURL := range []string{
		"https://localhost:7034",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponents(t, testCaseURL)
			testREDMetricsForNetHTTPSLibrary(t, testCaseURL, "dotnetserver") // reusing what we do for NodeJS
		})
	}
}

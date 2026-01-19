//go:build integration

package integration

import (
	"os"
	"path"
	"strconv"
	"testing"

	"github.com/grafana/beyla/v2/internal/test/integration/components/promtest"
	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

func testREDMetricsForNodeHTTPLibrary(t *testing.T, url, urlPath, comm, namespace string) {
	jsonBody, err := os.ReadFile(path.Join(pathRoot, "internal", "test", "integration", "components", "rusttestserver", "mid_data.json"))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(jsonBody), 100)

	// Call 3 times the instrumented service, forcing it to:
	// - take a large JSON file
	// - returning a 200 code
	for i := 0; i < 4; i++ {
		doHTTPPost(t, url+urlPath, 200, jsonBody)
	}

	// Eventually, Prometheus would make this query visible
	pq := promtest.Client{HostPort: prometheusHostPort}
	var results []promtest.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="POST",` +
			`http_response_status_code="200",` +
			`service_namespace="` + namespace + `",` +
			`service_name="` + comm + `",` +
			`url_path="` + urlPath + `"}`)
		require.NoError(t, err)
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 3, val)
		if len(results) > 0 {
			res := results[0]
			addr := res.Metric["client_address"]
			assert.NotNil(t, addr)
		}
	})
}

func testREDMetricsForNodeHTTPLibraryRoutes(t *testing.T, url, comm, namespace string) {
	slug := "/users/u"
	// Call 3 times the instrumented service, forcing it to:
	// - returning a 200 code
	for i := 0; i < 4; i++ {
		ti.DoHTTPGet(t, url+slug+strconv.Itoa(i), 200)
	}

	// Eventually, Prometheus would make this query visible
	pq := promtest.Client{HostPort: prometheusHostPort}
	var results []promtest.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="` + namespace + `",` +
			`service_name="` + comm + `",` +
			`http_route="/users/:userId"}`)
		require.NoError(t, err)
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 3, val)
		if len(results) > 0 {
			res := results[0]
			addr := res.Metric["client_address"]
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
			testREDMetricsForNodeHTTPLibrary(t, testCaseURL, "/greeting", "node", "integration-test")
			testREDMetricsForNodeHTTPLibraryRoutes(t, testCaseURL, "node", "integration-test")
		})
	}
}

func testREDMetricsNodeJSHTTPS(t *testing.T) {
	for _, testCaseURL := range []string{
		"https://localhost:3034",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponents(t, testCaseURL)
			testREDMetricsForNodeHTTPLibrary(t, testCaseURL, "/greeting", "node", "integration-test")
		})
	}
}

func checkReportedNodeJSEvents(t *testing.T, urlPath, comm, namespace string, numEvents int) {
	// Eventually, Prometheus would make this query visible
	pq := promtest.Client{HostPort: prometheusHostPort}
	var results []promtest.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="POST",` +
			`http_response_status_code="200",` +
			`service_namespace="` + namespace + `",` +
			`service_name="` + comm + `",` +
			`url_path="` + urlPath + `"}`)
		require.NoError(t, err)
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, val, numEvents)
		if len(results) > 0 {
			res := results[0]
			addr := res.Metric["client_address"]
			assert.NotNil(t, addr)
		}
	})
}

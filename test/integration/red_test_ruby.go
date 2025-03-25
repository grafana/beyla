//go:build integration

package integration

import (
	"testing"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v2/test/integration/components/prom"
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
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="POST",` +
			`http_response_status_code="201",` +
			`service_namespace="integration-test",` +
			`service_name="` + comm + `",` +
			`url_path="` + path + `"}`)
		require.NoError(t, err)
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 1, val)
		if len(results) > 0 {
			res := results[0]
			addr := res.Metric["client_address"]
			assert.NotNil(t, addr)
		}
	})

	// check that the resource attributes we passed made it for the service
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`target_info{` +
			`data_center="ca",` +
			`deployment_zone="to"}`)
		require.NoError(t, err)
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 1, val)
	})

	// Call 4 times the instrumented service, forcing it to:
	// - process multiple calls in a row with, one more than we might need
	// - returning a 200 code
	for i := 0; i < 4; i++ {
		doHTTPGet(t, url+path+"/1", 200)
	}

	// Eventually, Prometheus would make this query visible
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="integration-test",` +
			`service_name="` + comm + `",` +
			`http_route="/users/:user_id",` +
			`url_path="` + path + `/1"}`)
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

func testREDMetricsRailsHTTP(t *testing.T) {
	for _, testCaseURL := range []string{
		"http://localhost:3041",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForRubyTestComponents(t, testCaseURL)
			testREDMetricsForRubyHTTPLibrary(t, testCaseURL, "my-ruby-app")
		})
	}
}

func testREDMetricsRailsHTTPS(t *testing.T) {
	for _, testCaseURL := range []string{
		"https://localhost:3044",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForRubyTestComponents(t, testCaseURL)
			testREDMetricsForRubyHTTPLibrary(t, testCaseURL, "my-ruby-app")
		})
	}
}

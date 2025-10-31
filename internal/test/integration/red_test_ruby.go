//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ti "go.opentelemetry.io/obi/pkg/test/integration"

	"github.com/grafana/beyla/v2/internal/test/integration/components/jaeger"
	"github.com/grafana/beyla/v2/internal/test/integration/components/prom"
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

	// add couple of record to users, we will get records id of 1,2,3,4
	jsonBody := []byte(`{"name": "Jane Doe", "email": "jane@grafana.com"}`)
	doHTTPPost(t, url+path, 201, jsonBody)

	jsonBody = []byte(`{"name": "John Doe", "email": "john@grafana.com"}`)
	doHTTPPost(t, url+path, 201, jsonBody)

	jsonBody = []byte(`{"name": "Mary Doe", "email": "mary@grafana.com"}`)
	doHTTPPost(t, url+path, 201, jsonBody)

	jsonBody = []byte(`{"name": "Mark Doe", "email": "mark@grafana.com"}`)
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
		ti.DoHTTPGet(t, url+path+"/1", 200)
	}

	// Eventually, Prometheus would make this query visible
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="integration-test",` +
			`service_name="` + comm + `",` +
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

// Assumes we've run the metrics tests
func testHTTPTracesNestedNginx(t *testing.T) {
	for i := 1; i <= 4; i++ {
		go ti.DoHTTPGet(t, "https://localhost:8443/users/"+strconv.Itoa(i), 200)
	}

	for i := 1; i <= 4; i++ {
		slug := strconv.Itoa(i)
		var trace jaeger.Trace
		test.Eventually(t, testTimeout, func(t require.TestingT) {
			resp, err := http.Get(jaegerQueryURL + "?service=nginx&tags=%7B%22url.path%22%3A%22%2Fusers%2F" + slug + "%22%7D")
			require.NoError(t, err)
			if resp == nil {
				return
			}
			require.Equal(t, http.StatusOK, resp.StatusCode)
			var tq jaeger.TracesQuery
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
			traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/users/" + slug})
			require.GreaterOrEqual(t, len(traces), 1)
			trace = traces[0]

			// Check the information of the server span
			res := trace.FindByOperationName("GET /users/"+slug, "server")
			require.GreaterOrEqual(t, len(res), 1)
			server := res[0]
			require.NotEmpty(t, server.TraceID)
			require.NotEmpty(t, server.SpanID)

			// check client call
			res = trace.FindByOperationName("GET /users/"+slug, "client")
			require.GreaterOrEqual(t, len(res), 1)
			client := res[0]
			require.NotEmpty(t, client.TraceID)
			require.Equal(t, server.TraceID, client.TraceID)
			require.NotEmpty(t, client.SpanID)
		}, test.Interval(100*time.Millisecond))
	}
}

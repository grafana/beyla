//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ti "go.opentelemetry.io/obi/pkg/test/integration"

	"github.com/grafana/beyla/v2/internal/test/integration/components/docker"
	"github.com/grafana/beyla/v2/internal/test/integration/components/jaeger"
	"github.com/grafana/beyla/v2/internal/test/integration/components/prom"
)

// does a smoke test to verify that all the components that started
// asynchronously for the Elixir test are up and communicating properly
func waitForPHPTestComponents(t *testing.T, url string) {
	waitForTestComponentsSub(t, url, "/status")
}

func waitForPHPTraceTestComponents(t *testing.T, url string) {
	waitForTestComponentsSubStatus(t, url, "/hello", 404)
	waitForSQLTestComponentsMySQL(t, url, "/")
}

func testREDMetricsForPHPHTTPLibrary(t *testing.T, url string, nginx, php string) {
	path := "/ping"

	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result

	// Call 4 times the instrumented service, forcing it to:
	// - process multiple calls in a row with, one more than we might need
	// - returning a 200 code
	for i := 0; i < 4; i++ {
		ti.DoHTTPGet(t, fmt.Sprintf("%s%s", url, path), 200)
	}

	// Eventually, Prometheus would make this query visible
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="integration-test",` +
			`service_name="` + nginx + `",` +
			`http_route="/ping"}`)
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
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="integration-test",` +
			`service_name="` + php + `",` +
			`http_route="/ping"}`)
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
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_client_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="integration-test",` +
			`service_name="` + nginx + `",` +
			`http_route="/ping"}`)
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

func testREDMetricsPHPFPM(t *testing.T) {
	for _, testCaseURL := range []string{
		"http://localhost:8080",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForPHPTestComponents(t, testCaseURL)
			testREDMetricsForPHPHTTPLibrary(t, testCaseURL, "nginx", "php-fpm")
		})
	}
}

func TestPHPFM(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-php-fpm.yml", path.Join(pathOutput, "test-suite-php-fpm.log"))
	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `BEYLA_EXECUTABLE_NAME=`, `BEYLA_OPEN_PORT=`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	t.Run("PHP-FM RED metrics", testREDMetricsPHPFPM)

	require.NoError(t, compose.Close())
}

func testHTTPTracesPHP(t *testing.T) {
	for i := 0; i < 4; i++ {
		ti.DoHTTPGet(t, "http://localhost:8080/", 200)
	}

	var trace jaeger.Trace
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		resp, err := http.Get(jaegerQueryURL + "?service=nginx&operation=GET%20%2F")
		require.NoError(t, err)
		if resp == nil {
			return
		}
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/"})
		require.GreaterOrEqual(t, len(traces), 1)
		trace = traces[len(traces)-1]

		// Check the information of the parent span
		res := trace.FindByOperationNameAndService("GET /", "nginx")
		require.Len(t, res, 2)
		parent := res[0]
		require.NotEmpty(t, parent.TraceID)
		traceID := parent.TraceID
		require.NotEmpty(t, parent.SpanID)
		// check duration is at least 2us
		assert.Less(t, (2 * time.Microsecond).Microseconds(), parent.Duration)

		res = trace.FindByOperationNameAndService("GET /", "php-fpm")
		require.Len(t, res, 1)

		parent = res[0]
		require.NotEmpty(t, parent.TraceID)
		require.Equal(t, traceID, parent.TraceID)
		require.NotEmpty(t, parent.SpanID)

		res = trace.FindByOperationNameAndService("SELECT accounts", "php-fpm")
		require.Len(t, res, 1)

		parent = res[0]
		require.NotEmpty(t, parent.TraceID)
		require.Equal(t, traceID, parent.TraceID)
		require.NotEmpty(t, parent.SpanID)
	}, test.Interval(100*time.Millisecond))
}

func testTracesPHPFPM(t *testing.T) {
	for _, testCaseURL := range []string{
		"http://localhost:8080",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForPHPTraceTestComponents(t, testCaseURL)
			testHTTPTracesPHP(t)
		})
	}
}

func TestPHPFMUnixSock(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-php-fpm-sock.yml", path.Join(pathOutput, "test-suite-php-fpm-sock.log"))
	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `BEYLA_EXECUTABLE_NAME=`, `BEYLA_OPEN_PORT=`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	t.Run("PHP-FM Traces", testTracesPHPFPM)

	require.NoError(t, compose.Close())
}

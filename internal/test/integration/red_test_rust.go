//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"os"
	"path"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v2/internal/test/integration/components/jaeger"
	"github.com/grafana/beyla/v2/internal/test/integration/components/prom"
)

func testREDMetricsForRustHTTPLibrary(t *testing.T, url, comm, namespace string, port int, notraces bool) {
	jsonBody, err := os.ReadFile(path.Join(pathRoot, "internal", "test", "integration", "components", "rusttestserver", "mid_data.json"))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(jsonBody), 100)

	urlPath := "/greeting"

	// Call 4 times the instrumented service, forcing it to:
	// - take a large JSON body
	// - returning a 200 code
	for i := 0; i < 4; i++ {
		doHTTPPost(t, url+urlPath, 200, jsonBody)
	}

	// Eventually, Prometheus would make this query visible
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
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

	if notraces {
		return
	}

	// Add and check for specific trace ID
	traceID := createTraceID()
	parentID := createParentID()
	traceparent := createTraceparent(traceID, parentID)
	doHTTPGetWithTraceparent(t, url+"/trace", 200, traceparent)

	var trace jaeger.Trace
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		resp, err := http.Get(jaegerQueryURL + "?service=" + comm + "&operation=GET%20%2Ftrace")
		require.NoError(t, err)
		if resp == nil {
			return
		}
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/trace"})
		require.Len(t, traces, 1)
		trace = traces[0]
	}, test.Interval(100*time.Millisecond))

	// Check the information of the parent span
	res := trace.FindByOperationName("GET /trace", "server")
	require.Len(t, res, 1)
	parent := res[0]
	require.NotEmpty(t, parent.TraceID)
	require.Equal(t, traceID, parent.TraceID)

	// Validate that "parent" is a CHILD_OF the traceparent's "parent-id"
	childOfPID := trace.ChildrenOf(parentID)
	require.Len(t, childOfPID, 1)

	require.NotEmpty(t, parent.SpanID)
	// check duration is at least 2us
	assert.Less(t, (2 * time.Microsecond).Microseconds(), parent.Duration)
	// check span attributes
	sd := parent.Diff(
		jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"},
		jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(200)},
		jaeger.Tag{Key: "url.path", Type: "string", Value: "/trace"},
		jaeger.Tag{Key: "server.port", Type: "int64", Value: float64(port)},
		jaeger.Tag{Key: "http.route", Type: "string", Value: "/trace"},
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "server"},
	)
	assert.Empty(t, sd, sd.String())

	process := trace.Processes[parent.ProcessID]
	assert.Equal(t, comm, process.ServiceName)
	serviceInstance, ok := jaeger.FindIn(process.Tags, "service.instance.id")
	require.Truef(t, ok, "service.instance.id not found in tags: %v", process.Tags)
	assert.Regexp(t, `^beyla:\d+$$`, serviceInstance.Value)
	sd = jaeger.Diff([]jaeger.Tag{
		{Key: "otel.library.name", Type: "string", Value: "github.com/grafana/beyla"},
		{Key: "telemetry.sdk.language", Type: "string", Value: "rust"},
		{Key: "telemetry.sdk.name", Type: "string", Value: "beyla"},
		{Key: "service.namespace", Type: "string", Value: "integration-test"},
		serviceInstance,
	}, process.Tags)
	assert.Empty(t, sd, sd.String())
}

func validateLargeDownloadURLSeen(t *testing.T, comm, namespace, urlPath string) {
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
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
			assert.GreaterOrEqual(t, len(res.Value), 1)
			elapsed := res.Value[0]
			f, ok := elapsed.(float64)

			if ok {
				assert.GreaterOrEqual(t, f, 50000000.0) // must be 50ms or greater
			} else {
				t.FailNow()
			}
		}
	})
}

func testREDMetricsForLargeRustDownloads(t *testing.T, tURL, comm, namespace string) {
	for i := 0; i < 4; i++ {
		doHTTPGetFullResponse(t, tURL+"/large", 200)
		doHTTPGetFullResponse(t, tURL+"/download1", 200)
		doHTTPGetFullResponse(t, tURL+"/download2", 200)
	}

	validateLargeDownloadURLSeen(t, comm, namespace, "/large")
	validateLargeDownloadURLSeen(t, comm, namespace, "/download1")
	validateLargeDownloadURLSeen(t, comm, namespace, "/download2")
}

func testREDMetricsRustHTTP(t *testing.T) {
	for _, testCaseURL := range []string{
		"http://localhost:8091",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponents(t, testCaseURL)
			testREDMetricsForRustHTTPLibrary(t, testCaseURL, "greetings", "integration-test", 8090, false)
			testREDMetricsForLargeRustDownloads(t, testCaseURL, "greetings", "integration-test")
		})
	}
}

func testREDMetricsRustHTTPS(t *testing.T) {
	for _, testCaseURL := range []string{
		"https://localhost:8491",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponents(t, testCaseURL)
			testREDMetricsForRustHTTPLibrary(t, testCaseURL, "greetings", "integration-test", 8490, false)
			testREDMetricsForLargeRustDownloads(t, testCaseURL, "greetings", "integration-test")
		})
	}
}

func checkReportedRustEvents(t *testing.T, comm, namespace string, numEvents int) {
	jsonBody, err := os.ReadFile(path.Join(pathRoot, "internal", "test", "integration", "components", "rusttestserver", "mid_data.json"))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(jsonBody), 100)

	urlPath := "/greeting"

	// Eventually, Prometheus would make this query visible
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
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

func testREDMetricsForRustHTTP2Library(t *testing.T, url, comm, namespace string) {
	jsonBody, err := os.ReadFile(path.Join(pathRoot, "internal", "test", "integration", "components", "rusttestserver", "mid_data.json"))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(jsonBody), 100)

	urlPath := "/greeting"

	// Call 4 times the instrumented service, forcing it to:
	// - take a large JSON body
	// - returning a 200 code
	for i := 0; i < 4; i++ {
		doHTTP2Post(t, url+urlPath, 200, jsonBody)
	}

	// Eventually, Prometheus would make this query visible
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
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

func testREDMetricsRustHTTP2(t *testing.T) {
	for _, testCaseURL := range []string{
		"https://localhost:8491",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponentsHTTP2(t, testCaseURL)
			testREDMetricsForRustHTTP2Library(t, testCaseURL, "greetings", "integration-test")
		})
	}
}

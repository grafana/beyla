//go:build integration

package integration

import (
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/test/integration/components/jaeger"
	"github.com/grafana/beyla/test/integration/components/prom"
)

func testREDMetricsForRustHTTPLibrary(t *testing.T, url string, comm string, port int) {
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
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 3, val)
		if len(results) > 0 {
			res := results[0]
			addr := net.ParseIP(res.Metric["net_sock_peer_addr"])
			assert.NotNil(t, addr)
		}
	})

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
		traces := tq.FindBySpan(jaeger.Tag{Key: "http.target", Type: "string", Value: "/trace"})
		require.Len(t, traces, 1)
		trace = traces[0]
	}, test.Interval(100*time.Millisecond))

	// Check the information of the parent span
	res := trace.FindByOperationName("GET /trace")
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
	assert.Truef(t, parent.AllMatches(
		jaeger.Tag{Key: "otel.library.name", Type: "string", Value: "github.com/grafana/beyla"},
		jaeger.Tag{Key: "http.method", Type: "string", Value: "GET"},
		jaeger.Tag{Key: "http.status_code", Type: "int64", Value: float64(200)},
		jaeger.Tag{Key: "http.target", Type: "string", Value: "/trace"},
		jaeger.Tag{Key: "net.host.port", Type: "int64", Value: float64(port)},
		jaeger.Tag{Key: "http.route", Type: "string", Value: "/trace"},
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "server"},
	), "not all tags matched in %+v", parent.Tags)

	process := trace.Processes[parent.ProcessID]
	assert.Equal(t, comm, process.ServiceName)
	assert.Truef(t, jaeger.AllMatches(process.Tags, []jaeger.Tag{
		{Key: "telemetry.sdk.language", Type: "string", Value: "go"},
		{Key: "service.namespace", Type: "string", Value: "integration-test"},
	}), "not all tags matched in %+v", process.Tags)

}

func testREDMetricsRustHTTP(t *testing.T) {
	for _, testCaseURL := range []string{
		"http://localhost:8091",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponents(t, testCaseURL)
			testREDMetricsForRustHTTPLibrary(t, testCaseURL, "greetings", 8090)
		})
	}
}

func testREDMetricsRustHTTPS(t *testing.T) {
	for _, testCaseURL := range []string{
		"https://localhost:8491",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponents(t, testCaseURL)
			testREDMetricsForRustHTTPLibrary(t, testCaseURL, "greetings", 8490)
		})
	}
}

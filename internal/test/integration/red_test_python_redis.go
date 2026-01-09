//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"

	ti "go.opentelemetry.io/obi/pkg/test/integration"

	"github.com/grafana/beyla/v2/internal/test/integration/components/jaeger"
	"github.com/grafana/beyla/v2/internal/test/integration/components/prom"
)

func testREDMetricsForPythonRedisLibrary(t *testing.T, testCase TestCase) {
	url := testCase.Route
	urlPath := testCase.Subpath
	comm := testCase.Comm
	namespace := testCase.Namespace
	// Call 3 times the instrumented service, forcing it to:
	// - take a large JSON file
	// - returning a 200 code
	for i := 0; i < 4; i++ {
		ti.DoHTTPGet(t, url+"/"+urlPath, 200)
	}

	// Eventually, Prometheus would make redis operations visible
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	var err error
	for _, span := range testCase.Spans {
		test.Eventually(t, testTimeout, func(t require.TestingT) {
			var err error
			results, err = pq.Query(`db_client_operation_duration_seconds_count{` +
				`db_operation_name="` + span.Name + `",` +
				`service_namespace="` + namespace + `"}`)
			require.NoError(t, err, "failed to query prometheus for %s", span.Name)
			enoughPromResults(t, results)
			val := totalPromCount(t, results)
			assert.LessOrEqual(t, 3, val, "expected at least 3 %s operations, got %d", span.Name, val)
		})
	}

	// Ensure we don't see any http requests
	results, err = pq.Query(`http_server_request_duration_seconds_count{}`)
	require.NoError(t, err, "failed to query prometheus for http_server_request_duration_seconds_count")
	require.Empty(t, results, "expected no HTTP requests, got %d", len(results))
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		for _, span := range testCase.Spans {
			command := span.Name
			resp, err := http.Get(jaegerQueryURL + "?service=" + comm + "&operation=" + command)
			require.NoError(t, err, "failed to query jaeger for %s", command)
			if resp == nil {
				return
			}
			require.Equal(t, http.StatusOK, resp.StatusCode, "unexpected status code for %s: %d", command, resp.StatusCode)
			var tq jaeger.TracesQuery
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq), "failed to decode jaeger response for %s", command)
			var tags []jaeger.Tag
			for _, attr := range span.Attributes {
				tags = append(tags, otelAttributeToJaegerTag(attr))
			}
			traces := tq.FindBySpan(tags...)
			assert.LessOrEqual(t, 1, len(traces), "span %s with tags %v not found in traces in traces %v", command, tags, tq.Data)
		}
	}, test.Interval(100*time.Millisecond))

	// Ensure we don't find any HTTP traces, since we filter them out
	resp, err := http.Get(jaegerQueryURL + "?service=" + comm + "&operation=GET%20%2F" + urlPath)
	require.NoError(t, err, "failed to query jaeger for HTTP traces")
	if resp == nil {
		return
	}
	require.Equal(t, http.StatusOK, resp.StatusCode, "unexpected status code for HTTP traces: %d", resp.StatusCode)
	var tq jaeger.TracesQuery
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq), "failed to decode jaeger response for HTTP traces")
	traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/" + urlPath})
	require.Empty(t, traces, "expected no HTTP traces, got %d", len(traces))
}

func testREDMetricsPythonRedisOnly(t *testing.T) {
	redisCommonAttributes := []attribute.KeyValue{
		attribute.String("db.system.name", "redis"),
		attribute.String("span.kind", "client"),
		attribute.Int("server.port", 6379),
	}
	testCases := []TestCase{
		{
			Route:     "http://localhost:8381",
			Subpath:   "redis",
			Comm:      "python3.12",
			Namespace: "integration-test",
			Spans: []TestCaseSpan{
				{
					Name: "HSET",
					Attributes: []attribute.KeyValue{
						attribute.String("db.operation.name", "HSET"),
						attribute.String("db.query.text", "HSET user-session:123 name John surname Smith company Redis age 29"),
					},
				},
				{
					Name: "HGETALL",
					Attributes: []attribute.KeyValue{
						attribute.String("db.operation.name", "HGETALL"),
						attribute.String("db.query.text", "HGETALL user-session:123"),
					},
				},
				{
					Name: "SET",
					Attributes: []attribute.KeyValue{
						attribute.String("db.operation.name", "SET"),
						attribute.String("db.query.text", "SET obi rocks"),
					},
				},
				{
					Name: "GET",
					Attributes: []attribute.KeyValue{
						attribute.String("db.operation.name", "GET"),
						attribute.String("db.query.text", "GET obi"),
					},
				},
			},
		},
		{
			Route:     "http://localhost:8381",
			Subpath:   "redis-error",
			Comm:      "python3.12",
			Namespace: "integration-test",
			Spans: []TestCaseSpan{
				{
					Name: "INVALID_COMMAND",
					Attributes: []attribute.KeyValue{
						attribute.String("db.operation.name", "INVALID_COMMAND"),
						attribute.String("db.query.text", "INVALID_COMMAND"),
						attribute.Bool("error", true),
						attribute.String("db.response.status_code", "ERR"),
						attribute.String("otel.status_description", "ERR unknown command 'INVALID_COMMAND', with args beginning with: "),
					},
				},
				{
					Name: "SET",
					Attributes: []attribute.KeyValue{
						attribute.String("db.operation.name", "SET"),
						attribute.String("db.query.text", "SET obi-error rocks"),
					},
				},
				{
					Name: "LPUSH",
					Attributes: []attribute.KeyValue{
						attribute.String("db.operation.name", "LPUSH"),
						attribute.String("db.query.text", "LPUSH obi-error rocks more"),
						attribute.Bool("error", true),
						attribute.String("db.response.status_code", "WRONGTYPE"),
						attribute.String("otel.status_description", "WRONGTYPE Operation against a key holding the wrong kind of value"),
					},
				},
				{
					Name: "EVALSHA",
					Attributes: []attribute.KeyValue{
						attribute.String("db.operation.name", "EVALSHA"),
						attribute.String("db.query.text", "EVALSHA INVALID_SHA 0"),
						attribute.Bool("error", true),
						attribute.String("db.response.status_code", "NOSCRIPT"),
						attribute.String("otel.status_description", "NOSCRIPT No matching script. Please use EVAL."),
					},
				},
			},
		},
		{
			Route:     "http://localhost:8381",
			Subpath:   "redis-db",
			Comm:      "python3.12",
			Namespace: "integration-test",
			Spans: []TestCaseSpan{
				{
					Name: "SELECT",
					Attributes: []attribute.KeyValue{
						attribute.String("db.operation.name", "SELECT"),
						attribute.String("db.query.text", "SELECT 1"),
					},
				},
				{
					Name: "SET",
					Attributes: []attribute.KeyValue{
						attribute.String("db.operation.name", "SET"),
						attribute.String("db.query.text", "SET obi-db-1 rocks"),
						attribute.String("db.namespace", "1"),
					},
				},
				{
					Name: "GET",
					Attributes: []attribute.KeyValue{
						attribute.String("db.operation.name", "GET"),
						attribute.String("db.query.text", "GET obi-db-1"),
						attribute.String("db.namespace", "1"),
					},
				},
			},
		},
	}
	for _, testCase := range testCases {
		// Add common attributes to each span
		for i := range testCase.Spans {
			testCase.Spans[i].Attributes = append(testCase.Spans[i].Attributes, redisCommonAttributes...)
		}

		t.Run(testCase.Route, func(t *testing.T) {
			waitForRedisTestComponents(t, testCase.Route, "/"+testCase.Subpath)
			testREDMetricsForPythonRedisLibrary(t, testCase)
		})
	}
}

func waitForRedisTestComponents(t *testing.T, url string, subpath string) {
	pq := prom.Client{HostPort: prometheusHostPort}
	test.Eventually(t, 1*time.Minute, func(t require.TestingT) {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest(http.MethodGet, url+subpath, nil)
		require.NoError(t, err)
		r, err := testHTTPClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode)

		// now, verify that the metric has been reported.
		// we don't really care that this metric could be from a previous
		// test. Once one it is visible, it means that Otel and Prometheus are healthy
		results, err := pq.Query(`db_client_operation_duration_seconds_count{db_system_name="redis"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)
	}, test.Interval(time.Second))
}

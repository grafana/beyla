//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/test/integration/components/jaeger"
	"github.com/grafana/beyla/test/integration/components/prom"
)

func testClientWithMethodAndStatusCode(t *testing.T, method string, statusCode int, traces bool, traceIDLookup string) {
	// Eventually, Prometheus would make this query visible
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_client_request_duration_seconds_count{` +
			fmt.Sprintf(`http_request_method="%s",`, method) +
			fmt.Sprintf(`http_response_status_code="%d",`, statusCode) +
			`http_route="/oss/",` +
			`service_namespace="integration-test",` +
			`service_name="pingclient"}`)
		require.NoError(t, err)
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 1, val)
	})

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_client_request_body_size_bytes_count{` +
			fmt.Sprintf(`http_request_method="%s",`, method) +
			fmt.Sprintf(`http_response_status_code="%d",`, statusCode) +
			`http_route="/oss/",` +
			`service_namespace="integration-test",` +
			`service_name="pingclient"}`)
		require.NoError(t, err)
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 1, val)
	})

	if !traces {
		return
	}

	var trace jaeger.Trace
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		resp, err := http.Get(jaegerQueryURL + fmt.Sprintf("?service=pingclient&operation=%s", method))
		require.NoError(t, err)
		if resp == nil {
			return
		}
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(statusCode)})
		require.GreaterOrEqual(t, len(traces), 1)
		trace = traces[0]
	}, test.Interval(100*time.Millisecond))

	spans := trace.FindByOperationName(method)
	require.Len(t, spans, 1)
	span := spans[0]

	/*
	 The code in pingclient.go generates spans like these:
	 00-000000000000038b0000000000000000-000000000000038b-01

	 The traceID and spanID increase by one in tandem and it loops forever.
	 We check that the traceID has that 16 character 0 suffix and then we
	 use the first 16 characters for looking up by Parent span.
	*/
	require.True(t, span.TraceID != "")
	require.True(t, strings.HasSuffix(span.TraceID, traceIDLookup))
	require.True(t, strings.HasPrefix(span.SpanID, "00"))
}

func testREDMetricsForClientHTTPLibrary(t *testing.T) {
	testClientWithMethodAndStatusCode(t, "GET", 200, true, "0000000000000000")
	testClientWithMethodAndStatusCode(t, "OPTIONS", 204, true, "0000000000000001")
}

func testREDMetricsForClientHTTPLibraryNoTraces(t *testing.T) {
	testClientWithMethodAndStatusCode(t, "GET", 200, false, "0000000000000000")
	testClientWithMethodAndStatusCode(t, "OPTIONS", 204, false, "0000000000000001")
}

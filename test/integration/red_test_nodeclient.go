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

func testNodeClientWithMethodAndStatusCode(t *testing.T, method string, statusCode, port int, traceIDLookup string) {
	// Eventually, Prometheus would make this query visible
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_client_duration_seconds_count{` +
			fmt.Sprintf(`http_method="%s",`, method) +
			fmt.Sprintf(`http_status_code="%d",`, statusCode) +
			`service_namespace="integration-test",` +
			`service_name="node"}`)
		require.NoError(t, err)
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 1, val)
	})

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_client_request_size_bytes_count{` +
			fmt.Sprintf(`http_method="%s",`, method) +
			fmt.Sprintf(`http_status_code="%d",`, statusCode) +
			`service_namespace="integration-test",` +
			`service_name="node"}`)
		require.NoError(t, err)
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 1, val)
	})

	var trace jaeger.Trace
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		resp, err := http.Get(jaegerQueryURL + "?service=node")
		require.NoError(t, err)
		if resp == nil {
			return
		}
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "http.status_code", Type: "int64", Value: float64(statusCode)})
		require.GreaterOrEqual(t, len(traces), 1)
		trace = traces[0]
	}, test.Interval(100*time.Millisecond))

	spans := trace.FindByOperationName(method)
	require.Len(t, spans, 1)
	span := spans[0]

	assert.Truef(t, span.AllMatches(
		jaeger.Tag{Key: "otel.library.name", Type: "string", Value: "github.com/grafana/beyla"},
		jaeger.Tag{Key: "http.method", Type: "string", Value: "GET"},
		jaeger.Tag{Key: "http.status_code", Type: "int64", Value: float64(statusCode)},
		jaeger.Tag{Key: "http.url", Type: "string", Value: "/"},
		jaeger.Tag{Key: "net.peer.port", Type: "int64", Value: float64(port)},
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "client"},
	), "not all tags matched in %+v", span.Tags)

	/*
	 The code in client.js generates spans like these:
	 00-00000000000003810000000000000000-0000000000000381-01

	 The traceID and spanID increase by one in tandem and it loops forever.
	 We check that the traceID has that 16 character 0 suffix and then we
	 use the first 16 characters for looking up by Parent span.
	*/
	require.True(t, span.TraceID != "")
	require.True(t, strings.HasSuffix(span.TraceID, traceIDLookup))

	// The first 16 characters of traceID must match the spanID if client.js
	// generated the spans
	parent := span.TraceID[:16]
	childOfPID := trace.ChildrenOf(parent)
	require.Len(t, childOfPID, 1)
	childSpan := childOfPID[0]
	require.Equal(t, childSpan.TraceID, span.TraceID)
	require.Equal(t, childSpan.SpanID, span.SpanID)
}

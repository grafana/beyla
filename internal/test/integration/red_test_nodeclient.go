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

	"github.com/grafana/beyla/v2/internal/test/integration/components/jaeger"
	"github.com/grafana/beyla/v2/internal/test/integration/components/prom"
)

func testNodeClientWithMethodAndStatusCode(t *testing.T, method string, statusCode, port int, traceIDLookup string) {
	// Eventually, Prometheus would make this query visible
	var (
		pq     = prom.Client{HostPort: prometheusHostPort}
		labels = fmt.Sprintf(`http_request_method="%s",`, method) +
			fmt.Sprintf(`http_response_status_code="%d",`, statusCode) +
			`service_namespace="integration-test",` +
			`service_name="node"`
	)

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		query := fmt.Sprintf("http_client_request_duration_seconds_count{%s}", labels)
		checkClientPromQueryResult(t, pq, query, 1)
	})

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		query := fmt.Sprintf("http_client_request_body_size_bytes_count{%s}", labels)
		checkClientPromQueryResult(t, pq, query, 1)
	})

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		query := fmt.Sprintf("http_client_response_body_size_bytes_count{%s}", labels)
		checkClientPromQueryResult(t, pq, query, 1)
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
		tracesAll := tq.FindBySpan(jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(statusCode)})

		var traces []jaeger.Trace

		// Sometimes we can instrument between the connect and the data being sent
		// In that case we won't have enough info and we won't look in the parsed
		// traceID. We filter for that.
		for _, t := range tracesAll {
			if strings.HasPrefix(t.TraceID, "0000") {
				traces = append(traces, t)
			}
		}

		require.GreaterOrEqual(t, len(traces), 1)
		trace = traces[0]
	}, test.Interval(100*time.Millisecond))

	spans := trace.FindByOperationName(method+" /", "")
	require.Len(t, spans, 1)
	span := spans[0]

	urlFull := "http://grafana.com/"
	if port == 443 {
		urlFull = "https://grafana.com/"
	}

	sd := span.Diff(
		jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"},
		jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(statusCode)},
		jaeger.Tag{Key: "url.full", Type: "string", Value: urlFull},
		jaeger.Tag{Key: "server.port", Type: "int64", Value: float64(port)},
		jaeger.Tag{Key: "server.address", Type: "string", Value: "grafana.com"},
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "client"},
	)
	assert.Empty(t, sd, sd.String())

	/*
	 The code in client.js generates spans like these:
	 00-00000000000003810000000000000000-0000000000000381-01

	 The traceID and spanID increase by one in tandem and it loops forever.
	 We check that the traceID has that 16 character 0 suffix and then we
	 use the first 16 characters for looking up by Parent span.
	*/
	assert.NotEmpty(t, span.TraceID)
	assert.Truef(t, strings.HasSuffix(span.TraceID, traceIDLookup),
		"string %q should have suffix %q", span.TraceID, traceIDLookup)
}

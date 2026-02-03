//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v2/internal/test/integration/components/jaeger"
	"github.com/grafana/beyla/v2/internal/test/integration/components/promtest"
)

func testClientWithMethodAndStatusCode(t *testing.T, method string, statusCode int, traces bool) {
	// Eventually, Prometheus would make this query visible
	var (
		pq     = promtest.Client{HostPort: prometheusHostPort}
		labels = fmt.Sprintf(`http_request_method="%s",`, method) +
			fmt.Sprintf(`http_response_status_code="%d",`, statusCode) +
			`http_route="/oss/",` +
			`server_address="grafana.com",` +
			`service_namespace="integration-test",` +
			`service_name="pingclient"`
	)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		query := fmt.Sprintf("http_client_request_duration_seconds_count{%s}", labels)
		checkClientPromQueryResult(ct, pq, query, 1)
	}, testTimeout, 100*time.Millisecond)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		query := fmt.Sprintf("http_client_request_body_size_bytes_count{%s}", labels)
		checkClientPromQueryResult(ct, pq, query, 1)
	}, testTimeout, 100*time.Millisecond)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		query := fmt.Sprintf("http_client_response_body_size_bytes_count{%s}", labels)
		checkClientPromQueryResult(ct, pq, query, 1)
	}, testTimeout, 100*time.Millisecond)

	if !traces {
		return
	}

	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + fmt.Sprintf("?service=pingclient&operation=%s%%20/oss/", method))
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(statusCode)})
		require.GreaterOrEqual(ct, len(traces), 1)
		trace = traces[0]
	}, testTimeout, 100*time.Millisecond)

	spans := trace.FindByOperationName(method+" /oss/", "")
	require.Len(t, spans, 1)
	parent := spans[0]

	addr, ok := jaeger.FindIn(parent.Tags, "server.address")
	assert.True(t, ok)
	assert.Equal(t, "grafana.com", addr.Value)

	addr, ok = jaeger.FindIn(parent.Tags, "server.port")
	assert.True(t, ok)
	assert.EqualValues(t, 443, addr.Value)
}

func testREDMetricsForClientHTTPLibrary(t *testing.T) {
	testClientWithMethodAndStatusCode(t, "GET", 200, true)
	testClientWithMethodAndStatusCode(t, "OPTIONS", 204, true)
}

func testREDMetricsForClientHTTPLibraryNoTraces(t *testing.T) {
	testClientWithMethodAndStatusCode(t, "GET", 200, false)
	testClientWithMethodAndStatusCode(t, "OPTIONS", 204, false)
}

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
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v2/internal/test/integration/components/docker"
	"github.com/grafana/beyla/v2/internal/test/integration/components/jaeger"
	"github.com/grafana/beyla/v2/internal/test/integration/components/prom"
)

func testREDMetricsForHTTP2Library(t *testing.T, route, svcNs string) {
	// Eventually, Prometheus would make this query visible
	var (
		pq           = prom.Client{HostPort: prometheusHostPort}
		serverLabels = `http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="` + svcNs + `",` +
			`service_name="server",` +
			`http_route="` + route + `",` +
			`url_path="` + route + `"`
		clientLabels = `http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="` + svcNs + `",` +
			`service_name="client"`
	)

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		query := fmt.Sprintf("http_server_request_duration_seconds_count{%s}", serverLabels)
		checkServerPromQueryResult(t, pq, query, 1)
	})

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		query := fmt.Sprintf("http_server_request_body_size_bytes_count{%s}", serverLabels)
		checkServerPromQueryResult(t, pq, query, 3)
	})

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		query := fmt.Sprintf("http_server_response_body_size_bytes_count{%s}", serverLabels)
		checkServerPromQueryResult(t, pq, query, 3)
	})

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		query := fmt.Sprintf("http_client_request_duration_seconds_count{%s}", clientLabels)
		checkClientPromQueryResult(t, pq, query, 1)
	})

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		query := fmt.Sprintf("http_client_request_body_size_bytes_count{%s}", clientLabels)
		checkClientPromQueryResult(t, pq, query, 1)
	})

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		query := fmt.Sprintf("http_client_response_body_size_bytes_count{%s}", clientLabels)
		checkClientPromQueryResult(t, pq, query, 1)
	})
}

func testNestedHTTP2Traces(t *testing.T, url string) {
	var traceID string

	var trace jaeger.Trace
	test.Eventually(t, time.Duration(1)*time.Minute, func(t require.TestingT) {
		resp, err := http.Get(jaegerQueryURL + "?service=client&operation=GET%20%2F" + url)
		require.NoError(t, err)
		if resp == nil {
			return
		}
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"})
		require.GreaterOrEqual(t, len(traces), 1)
		trace = traces[0]
	}, test.Interval(100*time.Millisecond))

	// Check the information of the HTTP2 client span
	res := trace.FindByOperationName("GET /"+url, "client")
	require.Len(t, res, 1)
	parent := res[0]
	require.NotEmpty(t, parent.TraceID)
	traceID = parent.TraceID
	require.NotEmpty(t, parent.SpanID)

	// Find the same traceID on a server span
	test.Eventually(t, time.Duration(1)*time.Minute, func(t require.TestingT) {
		resp, err := http.Get(jaegerQueryURL + "?service=server&operation=GET%20%2F" + url + "&traceID=" + traceID)
		require.NoError(t, err)
		if resp == nil {
			return
		}
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"})
		require.GreaterOrEqual(t, len(traces), 1)
		trace = traces[0]
	}, test.Interval(100*time.Millisecond))
}

func TestHTTP2Go(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-http2.yml", path.Join(pathOutput, "test-suite-http2.log"))
	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `BEYLA_EXECUTABLE_NAME=`, `BEYLA_OPEN_PORT=`)
	lockdown := KernelLockdownMode()

	if !lockdown {
		compose.Env = append(compose.Env, `SECURITY_CONFIG_SUFFIX=_none`)
	}

	require.NoError(t, err)
	require.NoError(t, compose.Up())

	t.Run("Go RED metrics: http2 service", func(t *testing.T) {
		testREDMetricsForHTTP2Library(t, "/ping", "http2-go")
		testREDMetricsForHTTP2Library(t, "/pingdo", "http2-go")
		testREDMetricsForHTTP2Library(t, "/pingrt", "http2-go")
	})

	if !lockdown {
		t.Run("Go RED metrics: http2 context propagation ", func(t *testing.T) {
			testNestedHTTP2Traces(t, "pingdo")
		})
	}

	require.NoError(t, compose.Close())
}

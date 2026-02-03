// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v2/internal/test/integration/components/docker"
	"github.com/grafana/beyla/v2/internal/test/integration/components/promtest"
)

func TestPerAppFeatures(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-perapp.yml",
		path.Join(pathOutput, "test-suite-multiexec-perapp.log"))
	require.NoError(t, err)

	require.NoError(t, compose.Up())

	t.Run("OTEL exporter", func(t *testing.T) {
		testPerAppFeatures(t, "otel")
	})
	t.Run("Prometheus exporter", func(t *testing.T) {
		testPerAppFeatures(t, "prometheus")
	})

	require.NoError(t, compose.Close())
}

func testPerAppFeatures(t *testing.T, exportedSource string) {
	t.Run("all the services have span metrics", func(t *testing.T) {
		checkSpanMetric(t, 3*time.Minute, exportedSource, "node", 3031, "/testing-node")
		checkSpanMetric(t, time.Minute, exportedSource, "ruby", 3041, "/testing-rails")
		checkSpanMetric(t, time.Minute, exportedSource, "pytestserver", 7773, "/testing-python")
		checkSpanMetric(t, time.Minute, exportedSource, "testserver", 8080, "/testing-go")
		checkSpanMetric(t, time.Minute, exportedSource, "jtestserver", 8086, "/testing-java")
		checkSpanMetric(t, time.Minute, exportedSource, "rtestserver", 8091, "/testing-rust")
	})
	t.Run("node, rails and python have RED metrics", func(t *testing.T) {
		hasREDMetrics(t, exportedSource, "node", "/testing-node")
		hasREDMetrics(t, exportedSource, "ruby", "/testing-rails")
		hasREDMetrics(t, exportedSource, "pytestserver", "/testing-python")
	})
	t.Run("rest of services don't have RED metrics", func(t *testing.T) {
		hasNotREDMetrics(t, "testserver")
		hasNotREDMetrics(t, "jtestserver")
		hasNotREDMetrics(t, "rtestserver")
	})
}

var pq = promtest.Client{HostPort: prometheusHostPort}

func checkSpanMetric(t *testing.T, timeout time.Duration, exportedSource, serviceName string, port int, path string) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://localhost:%d%s", port, path), nil)
		require.NoError(ct, err)
		_, err = testHTTPClient.Do(req)
		require.NoError(ct, err)

		results, err := pq.Query(`traces_spanmetrics_latency_sum{exported="` + exportedSource +
			`",service_name="` + serviceName + `",span_name="GET ` + path + `"}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)
	}, timeout, time.Second)
}

func hasREDMetrics(t *testing.T, exportedSource, serviceName string, path string) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`http_server_request_body_size_bytes_sum{exported="` + exportedSource +
			`",service_name="` + serviceName + `",http_route="` + path + `"}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)
	}, time.Minute, time.Second)
}

func hasNotREDMetrics(t *testing.T, serviceName string) {
	results, err := pq.Query(`http_server_request_body_size_bytes_sum{service_name="` + serviceName + `"}`)
	require.NoError(t, err)
	require.Empty(t, results)
}

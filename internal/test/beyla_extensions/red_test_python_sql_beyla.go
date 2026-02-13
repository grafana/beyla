//go:build ignore

// Beyla-specific Python SQL RED metrics test helpers
// This file is copied to internal/testgenerated/integration/ by generate-obi-tests.sh

package integration

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ti "go.opentelemetry.io/obi/pkg/test/integration"

	"github.com/grafana/beyla/v3/internal/testgenerated/integration/components/jaeger"
	"github.com/grafana/beyla/v3/internal/testgenerated/integration/components/promtest"
)

func testREDMetricsForPythonSQLLibrary(t *testing.T, url, comm, namespace string) {
	urlPath := "/query"

	// Call 3 times the instrumented service, forcing it to:
	// - take a large JSON file
	// - returning a 200 code
	for i := 0; i < 4; i++ {
		ti.DoHTTPGet(t, url+urlPath, 200)
	}

	// Eventually, Prometheus would make this query visible
	pq := promtest.Client{HostPort: prometheusHostPort}
	var results []promtest.Result
	var err error
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`db_client_operation_duration_seconds_count{` +
			`db_operation_name="SELECT",` +
			`service_namespace="` + namespace + `"}`)
		require.NoError(t, err)
		enoughPromResults(t, results)
		val := totalPromCount(t, results)
		assert.LessOrEqual(t, 3, val)
	})

	// Ensure we don't see any http requests
	results, err = pq.Query(`http_server_request_duration_seconds_count{}`)
	require.NoError(t, err)
	require.Equal(t, len(results), 0)

	// Look for a trace with SELECT accounting.contacts
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		resp, err := http.Get(jaegerQueryURL + "?service=" + comm + "&operation=SELECT%20accounting.contacts")
		require.NoError(t, err)
		if resp == nil {
			return
		}
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "db.operation.name", Type: "string", Value: "SELECT"})
		assert.LessOrEqual(t, 1, len(traces))
	}, test.Interval(100*time.Millisecond))

	// Ensure we don't find any HTTP traces, since we filter them out
	resp, err := http.Get(jaegerQueryURL + "?service=" + comm + "&operation=GET%20%2Fquery")
	require.NoError(t, err)
	if resp == nil {
		return
	}
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var tq jaeger.TracesQuery
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
	traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/query"})
	require.Len(t, traces, 0)
}

func testREDMetricsPythonSQLOnly(t *testing.T) {
	for _, testCaseURL := range []string{
		"http://localhost:8381",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForSQLTestComponents(t, testCaseURL, "/query")
			testREDMetricsForPythonSQLLibrary(t, testCaseURL, "python3.14", "integration-test")
		})
	}
}

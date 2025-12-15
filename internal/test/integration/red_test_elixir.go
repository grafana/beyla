//go:build integration

package integration

import (
	"fmt"
	"testing"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ti "go.opentelemetry.io/obi/pkg/test/integration"

	"github.com/grafana/beyla/v2/internal/test/integration/components/prom"
)

// does a smoke test to verify that all the components that started
// asynchronously for the Elixir test are up and communicating properly
func waitForElixirTestComponents(t *testing.T, url string) {
	waitForTestComponentsSub(t, url, "/smoke")
}

func testREDMetricsForElixirHTTPLibrary(t *testing.T, url string, comm string) {
	path := "/test"

	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result

	// Call 4 times the instrumented service, forcing it to:
	// - process multiple calls in a row with, one more than we might need
	// - returning a 200 code
	for i := 0; i < 4; i++ {
		ti.DoHTTPGet(t, fmt.Sprintf("%s%s/%d", url, path, i), 200)
	}

	// Eventually, Prometheus would make this query visible
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="integration-test",` +
			`service_name="` + comm + `",` +
			`http_route="/test/:test_id"}`)
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

func testREDMetricsElixirHTTP(t *testing.T) {
	for _, testCaseURL := range []string{
		"http://localhost:4000",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForElixirTestComponents(t, testCaseURL)
			testREDMetricsForElixirHTTPLibrary(t, testCaseURL, "beam.smp")
		})
	}
}

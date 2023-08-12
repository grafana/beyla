//go:build integration

package integration

import (
	"strconv"
	"testing"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/ebpf-autoinstrument/test/integration/components/prom"
)

func testREDMetricsForClientHTTPLibrary(t *testing.T) {
	// Eventually, Prometheus would make this query visible
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_client_duration_seconds_count{` +
			`http_method="GET",` +
			`http_status_code="200",` +
			`service_namespace="integration-test",` +
			`service_name="pingclient"}`)
		require.NoError(t, err)
		// check duration_count has 3 calls and all the arguments
		require.Len(t, results, 1)
		res := results[0]
		val, err := strconv.Atoi(res.Value[1].(string))
		require.NoError(t, err)
		require.Len(t, res.Value, 2)
		assert.LessOrEqual(t, 1, val)
	})

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_client_request_size_bytes_count{` +
			`http_method="GET",` +
			`http_status_code="200",` +
			`service_namespace="integration-test",` +
			`service_name="pingclient"}`)
		require.NoError(t, err)
		// check duration_count has 3 calls and all the arguments
		require.Len(t, results, 1)
		res := results[0]
		val, err := strconv.Atoi(res.Value[1].(string))
		require.NoError(t, err)
		require.Len(t, res.Value, 2)
		assert.LessOrEqual(t, 1, val)
	})
}

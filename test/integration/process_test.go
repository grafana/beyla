//go:build integration

package integration

import (
	"strconv"
	"testing"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/test/integration/components/prom"
)

func testProcesses(attribMatcher map[string]string) func(t *testing.T) {
	return func(t *testing.T) {
		pq := prom.Client{HostPort: prometheusHostPort}
		utilizationLen := 0
		test.Eventually(t, testTimeout, func(t require.TestingT) {
			results, err := pq.Query(`process_cpu_utilization_ratio`)
			require.NoError(t, err)
			matchAttributes(t, results, attribMatcher)
			utilizationLen = len(results)
		})
		// given the low load of the unit tests, process_cpu_utilization ratio is a gauge with
		// zero as the most possible value, but process_cpu_time is a counter that shouldn't be
		// zero
		test.Eventually(t, testTimeout, func(t require.TestingT) {
			results, err := pq.Query(`process_cpu_time_seconds_total`)
			require.NoError(t, err)
			matchAttributes(t, results, attribMatcher)
			assert.Len(t, results, utilizationLen)
			// in multi-process services (e.g. Python gunicorn) we don't
			// generate so much load to make all the processes to have
			// CPU time > 0, so we evaluate the sum of all the values
			cpuSum := float64(0)
			for _, result := range results {
				require.Len(t, result.Value, 2) // timestamp and value
				val, err := strconv.ParseFloat(result.Value[1].(string), 64)
				require.NoError(t, err)
				cpuSum += val
			}
			assert.Greater(t, cpuSum, 0.0)
		})
	}
}

func matchAttributes(t require.TestingT, results []prom.Result, attribMatcher map[string]string) {
	assert.NotEmpty(t, results)
	for _, result := range results {
		for k, v := range attribMatcher {
			assert.Equalf(t, v, result.Metric[k], "attribute %v expected to be %v", k, v)
		}
	}
}

//go:build integration

package integration

import (
	"strconv"
	"testing"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v2/internal/test/integration/components/prom"
)

func testProcesses(attribMatcher map[string]string) func(t *testing.T) {
	return func(t *testing.T) {
		pq := prom.Client{HostPort: prometheusHostPort}
		utilizationLen := 0
		// cpu load is so low in integration tests that we don't check if the
		// value is > 0
		test.Eventually(t, testTimeout, func(t require.TestingT) {
			results, err := pq.Query(`process_cpu_utilization_ratio`)
			require.NoError(t, err)
			matchAttributes(t, results, attribMatcher)
			utilizationLen = len(results)
		})
		test.Eventually(t, testTimeout, func(t require.TestingT) {
			results, err := pq.Query(`process_cpu_time_seconds_total`)
			require.NoError(t, err)
			matchAttributes(t, results, attribMatcher)
			assert.Len(t, results, utilizationLen)
		})
		// checking that the memory is present and has a reasonable values
		memory := map[string]int{}
		test.Eventually(t, testTimeout, func(t require.TestingT) {
			results, err := pq.Query(`process_memory_usage_bytes`)
			require.NoError(t, err)
			matchAttributes(t, results, attribMatcher)
			// any of the processes used in the integration tests
			// should take more than 1MB of memory
			for _, result := range results {
				physicalMem, err := strconv.Atoi(result.Value[1].(string))
				require.NoError(t, err)
				require.Greater(t, physicalMem, 1_000_000)
				memory[result.Metric["service_instance_id"]] = physicalMem
			}
		})
		// checking that virtual memory has larger value than physical memory
		test.Eventually(t, testTimeout, func(t require.TestingT) {
			results, err := pq.Query(`process_memory_virtual_bytes`)
			require.NoError(t, err)
			matchAttributes(t, results, attribMatcher)
			for _, result := range results {
				virtualMem, err := strconv.Atoi(result.Value[1].(string))
				require.NoError(t, err)
				physicalMem, ok := memory[result.Metric["service_instance_id"]]
				require.Truef(t, ok, "did not find physical memory for process %s",
					result.Metric["service_instance_id"])
				require.Greater(t, virtualMem, physicalMem)
			}
		})
		test.Eventually(t, testTimeout, func(t require.TestingT) {
			results, err := pq.Query(`process_disk_io_bytes_total`)
			require.NoError(t, err)
			matchAttributes(t, results, attribMatcher)
		})
		test.Eventually(t, testTimeout, func(t require.TestingT) {
			results, err := pq.Query(`process_network_io_bytes_total`)
			require.NoError(t, err)
			matchAttributes(t, results, attribMatcher)
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

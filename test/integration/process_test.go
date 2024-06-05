package integration

import (
	"testing"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/test/integration/components/prom"
)

func testProcesses(attribMatcher map[string]string) func(t *testing.T) {
	return func(t *testing.T) {
		pq := prom.Client{HostPort: prometheusHostPort}
		var results []prom.Result
		test.Eventually(t, testTimeout, func(t require.TestingT) {
			var err error
			results, err = pq.Query(`process_cpu_utilization_ratio`)
			require.NoError(t, err)
			assert.NotEmpty(t, results)
			for _, result := range results {
				for k, v := range attribMatcher {
					assert.Equalf(t, v, result.Metric[k], "attribute %v expected to be %v", k, v)
				}
			}
		})
	}
}

//go:build integration

package integration

import (
	"net/http"
	"testing"

	"github.com/mariomac/guara/pkg/test"
	"github.com/prometheus/common/expfmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	flushesMetricName            = "ebpf_tracer_flushes"
	internalPrometheusMetricsURL = "http://localhost:8999/internal/metrics"
)

func testInternalPrometheusExport(t *testing.T) {
	// tests that internal metrics are properly exposed and updated
	initialFlushedRecords := getFlushesSum(t)
	for i := 0; i < 7; i++ {
		doHTTPGet(t, instrumentedServiceStdURL+"/testing/some/flushes", http.StatusOK)
	}
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		endFlushedRecords := getFlushesSum(t)
		// we use LessOrEqual because other elements could have been flushed
		// from other tests. The correct count of flushes is being tested in the unit
		// tests, so we just test here that the metrics are properly exported.
		assert.LessOrEqual(t, 7, endFlushedRecords-initialFlushedRecords,
			"%d - %d should be >= 7", endFlushedRecords, initialFlushedRecords)
	})
}

func getFlushesSum(t require.TestingT) int {
	parser := expfmt.TextParser{}
	resp, err := http.Get(internalPrometheusMetricsURL)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	metrics, err := parser.TextToMetricFamilies(resp.Body)
	require.NoError(t, err)
	flushHistogram, ok := metrics[flushesMetricName]
	if !ok {
		// might happen if no metrics are reported. Then returning zero
		return 0
	}
	flushMetrics := flushHistogram.Metric
	require.Len(t, flushMetrics, 1)
	flush := flushMetrics[0].Histogram
	require.NotNilf(t, flush, "original value", flushMetrics[0])
	return int(*flush.SampleSum)
}

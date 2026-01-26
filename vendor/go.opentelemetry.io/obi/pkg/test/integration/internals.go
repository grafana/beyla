// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"net/http"
	"testing"

	"github.com/mariomac/guara/pkg/test"
	io_prometheus_client "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	flushesMetricName            = "_ebpf_tracer_flushes"
	promRequestsMetricName       = "_prometheus_http_requests_total"
	internalPrometheusMetricsURL = "http://localhost:8999/internal/metrics"
)

// InternalPrometheusExport tests that internal metrics are properly exposed and updated
func InternalPrometheusExport(t *testing.T, config *TestConfig) {
	// Use config-specific metric names
	flushesMetricName := config.MetricPrefix + flushesMetricName
	promRequestsMetricName := config.MetricPrefix + promRequestsMetricName

	// tests that internal metrics are properly exposed and updated
	initialFlushedRecords := metricValue(t, flushesMetricName, nil)
	for i := 0; i < 7; i++ {
		DoHTTPGet(t, instrumentedServiceStdURL+"/testing/some/flushes", http.StatusOK)
	}
	eventuallyIterations := 0
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		eventuallyIterations++
		endFlushedRecords := metricValue(t, flushesMetricName, nil)
		// we use LessOrEqual because other elements could have been flushed
		// from other tests. The correct count of flushes is being tested in the unit
		// tests, so we just test here that the metrics are properly exported.
		assert.LessOrEqual(t, 7, endFlushedRecords-initialFlushedRecords,
			"%d - %d should be >= 7", endFlushedRecords, initialFlushedRecords)
	})

	// also testing the internal instrumentation of the prometheus export
	// prometheus metrics endpoint must have been invoked once at the beginning of the test,
	// plus once each eventually try
	assert.Equal(t, 1+eventuallyIterations,
		metricValue(t, promRequestsMetricName, map[string]string{"port": "8999", "path": "/internal/metrics"}),
	)
}

func metricValue(t require.TestingT, metricName string, labels map[string]string) int {
	parser := expfmt.NewTextParser(model.UTF8Validation)
	resp, err := http.Get(internalPrometheusMetricsURL)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	metrics, err := parser.TextToMetricFamilies(resp.Body)
	require.NoError(t, err)
	metricFamily, ok := metrics[metricName]
	if !ok {
		// might happen if no metrics are reported. Then returning zero
		return 0
	}
	matchingMetrics := filterMetrics(metricFamily, labels)
	require.Len(t, matchingMetrics, 1,
		"labels set matched multiple metrics. You must refine the search to match only one")
	val := getVal(matchingMetrics[0])
	require.NotNil(t, val, "original value", matchingMetrics[0])
	return int(*val)
}

func filterMetrics(metricFamily *io_prometheus_client.MetricFamily, labels map[string]string) []*io_prometheus_client.Metric {
	if len(labels) == 0 {
		return metricFamily.Metric
	}
	var matchingMetrics []*io_prometheus_client.Metric
metricsLoop:
	for _, metric := range metricFamily.Metric {
		for _, lbl := range metric.Label {
			if val, ok := labels[lbl.GetName()]; !ok || val != lbl.GetValue() {
				continue metricsLoop
			}
		}
		matchingMetrics = append(matchingMetrics, metric)
	}
	return matchingMetrics
}

func getVal(m *io_prometheus_client.Metric) *float64 {
	if m.Histogram != nil {
		return m.Histogram.SampleSum
	}
	if m.Counter != nil {
		return m.Counter.Value
	}
	panic("please implement the missing type to make your tests pass")
}

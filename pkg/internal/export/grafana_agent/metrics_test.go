package grafanaagent

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"

	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/request"
)

func TestGenerateMetrics(t *testing.T) {
	cfg := &otel.MetricsConfig{}
	start := time.Now()
	span := &request.Span{
		Type:         request.EventTypeHTTP,
		RequestStart: start.UnixNano(),
		End:          start.Add(3 * time.Second).UnixNano(),
		Method:       "GET",
		Status:       200,
	}

	metrics := generateMetrics(cfg, span)
	resourceMetrics := metrics.ResourceMetrics()
	assert.Equal(t, 1, resourceMetrics.Len())
	rm := resourceMetrics.At(0)
	scopeMetrics := rm.ScopeMetrics()
	assert.Equal(t, 1, scopeMetrics.Len())
	ilm := scopeMetrics.At(0)
	scopeName := ilm.Scope().Name()
	assert.Equal(t, otel.ReporterName, scopeName)
	metricsList := ilm.Metrics()
	assert.Equal(t, 2, metricsList.Len())

	// Assert histogram metric
	histogramMetric := metricsList.At(0)
	assert.Equal(t, otel.HTTPServerDuration, histogramMetric.Name())
	assert.Equal(t, "s", histogramMetric.Unit())
	assert.Equal(t, pmetric.AggregationTemporalityCumulative, histogramMetric.Histogram().AggregationTemporality())

	// Assert data point properties
	dataPoints := histogramMetric.Histogram().DataPoints()
	assert.Equal(t, 1, dataPoints.Len())
	dp := dataPoints.At(0)
	assert.Equal(t, 3.0, dp.Sum())

	// Assert metric attributes
	attributes := dp.Attributes()
	expectedAttrs := pcommon.NewMap()
	expectedAttrs.PutStr(string(otel.HTTPRequestMethodKey), "GET")
	expectedAttrs.PutInt(string(otel.HTTPResponseStatusCodeKey), 200)
	assert.Equal(t, expectedAttrs, attributes)
}
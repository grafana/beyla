package grafanaagent

import (
	"testing"
	"time"

	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

func TestGenerateMetrics(t *testing.T) {
	cfg := &otel.MetricsConfig{}
	span := &request.Span{
		Type:         request.EventTypeHTTP,
		RequestStart: time.Now().UnixNano(),
		End:          time.Now().Add(time.Second).UnixNano(),
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
	assert.Equal(t, 1, metricsList.Len())

	// Assert histogram metric
	histogramMetric := metricsList.At(0)
	assert.Equal(t, otel.HTTPServerDuration, histogramMetric.Name())
	assert.Equal(t, "s", histogramMetric.Unit())
	assert.Equal(t, pmetric.AggregationTemporalityDelta, histogramMetric.Histogram().AggregationTemporality())

	// Assert data point properties
	dataPoints := histogramMetric.Histogram().DataPoints()
	assert.Equal(t, 1, dataPoints.Len())
	dp := dataPoints.At(0)
	assert.Equal(t, float64(time.Second), dp.Count())

	//assert.Equal(t, pcommon.NewTimestampFromTime(span.Timings.RequestStart), dp.StartTimestamp())

	// Assert metric attributes
	attributes := dp.Attributes()
	expectedAttrs := pcommon.NewMap()
	expectedAttrs.PutStr(string(otel.HTTPRequestMethodKey), "GET")
	expectedAttrs.PutInt(string(otel.HTTPResponseStatusCodeKey), 200)
	assert.Equal(t, expectedAttrs, attributes)
}

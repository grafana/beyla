// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otelcfg // import "go.opentelemetry.io/obi/pkg/export/otel/otelcfg"

import (
	"context"

	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
)

// ConsumerExporter is an sdkmetric.Exporter that sends metrics to a collector consumer.
// It converts SDK metric data to collector pmetric format.
type ConsumerExporter struct {
	consumer consumer.Metrics
}

// NewConsumerExporter creates a new ConsumerExporter that wraps the given consumer.
func NewConsumerExporter(c consumer.Metrics) *ConsumerExporter {
	return &ConsumerExporter{consumer: c}
}

// Temporality returns the temporality to use for the given instrument kind.
func (e *ConsumerExporter) Temporality(_ sdkmetric.InstrumentKind) metricdata.Temporality {
	// Default to cumulative temporality for all instrument kinds
	return metricdata.CumulativeTemporality
}

// Aggregation returns the aggregation to use for the given instrument kind.
func (e *ConsumerExporter) Aggregation(kind sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return sdkmetric.DefaultAggregationSelector(kind)
}

// Export converts SDK metrics to pmetric and sends to the consumer.
func (e *ConsumerExporter) Export(ctx context.Context, rm *metricdata.ResourceMetrics) error {
	if e.consumer == nil {
		return nil
	}
	pm := convertResourceMetrics(rm)
	return e.consumer.ConsumeMetrics(ctx, pm)
}

// ForceFlush is a no-op for this exporter.
func (e *ConsumerExporter) ForceFlush(_ context.Context) error {
	return nil
}

// Shutdown is a no-op for this exporter.
func (e *ConsumerExporter) Shutdown(_ context.Context) error {
	return nil
}

// convertResourceMetrics converts SDK ResourceMetrics to pmetric.Metrics
func convertResourceMetrics(rm *metricdata.ResourceMetrics) pmetric.Metrics {
	pm := pmetric.NewMetrics()
	if rm == nil {
		return pm
	}

	prm := pm.ResourceMetrics().AppendEmpty()

	// Convert resource attributes
	convertResource(rm.Resource, prm.Resource())

	// Convert scope metrics
	for _, sm := range rm.ScopeMetrics {
		psm := prm.ScopeMetrics().AppendEmpty()
		psm.Scope().SetName(sm.Scope.Name)
		psm.Scope().SetVersion(sm.Scope.Version)

		// Convert metrics
		for _, m := range sm.Metrics {
			convertMetric(m, psm.Metrics())
		}
	}

	return pm
}

// convertResource converts SDK resource to pcommon.Resource
func convertResource(sdkRes *resource.Resource, pRes pcommon.Resource) {
	if sdkRes == nil {
		return
	}
	for _, kv := range sdkRes.Attributes() {
		convertAttribute(kv, pRes.Attributes())
	}
}

// convertAttribute converts a single SDK attribute to pcommon.Map
func convertAttribute(kv attribute.KeyValue, attrs pcommon.Map) {
	key := string(kv.Key)
	switch kv.Value.Type() {
	case attribute.BOOL:
		attrs.PutBool(key, kv.Value.AsBool())
	case attribute.INT64:
		attrs.PutInt(key, kv.Value.AsInt64())
	case attribute.FLOAT64:
		attrs.PutDouble(key, kv.Value.AsFloat64())
	case attribute.STRING:
		attrs.PutStr(key, kv.Value.AsString())
	case attribute.BOOLSLICE:
		slice := attrs.PutEmptySlice(key)
		for _, v := range kv.Value.AsBoolSlice() {
			slice.AppendEmpty().SetBool(v)
		}
	case attribute.INT64SLICE:
		slice := attrs.PutEmptySlice(key)
		for _, v := range kv.Value.AsInt64Slice() {
			slice.AppendEmpty().SetInt(v)
		}
	case attribute.FLOAT64SLICE:
		slice := attrs.PutEmptySlice(key)
		for _, v := range kv.Value.AsFloat64Slice() {
			slice.AppendEmpty().SetDouble(v)
		}
	case attribute.STRINGSLICE:
		slice := attrs.PutEmptySlice(key)
		for _, v := range kv.Value.AsStringSlice() {
			slice.AppendEmpty().SetStr(v)
		}
	}
}

// convertMetric converts a single SDK metric to pmetric.MetricSlice
func convertMetric(m metricdata.Metrics, pms pmetric.MetricSlice) {
	pm := pms.AppendEmpty()
	pm.SetName(m.Name)
	pm.SetDescription(m.Description)
	pm.SetUnit(m.Unit)

	switch data := m.Data.(type) {
	case metricdata.Gauge[int64]:
		convertGaugeInt64(data, pm)
	case metricdata.Gauge[float64]:
		convertGaugeFloat64(data, pm)
	case metricdata.Sum[int64]:
		convertSumInt64(data, pm)
	case metricdata.Sum[float64]:
		convertSumFloat64(data, pm)
	case metricdata.Histogram[int64]:
		convertHistogramInt64(data, pm)
	case metricdata.Histogram[float64]:
		convertHistogramFloat64(data, pm)
	case metricdata.ExponentialHistogram[int64]:
		convertExponentialHistogramInt64(data, pm)
	case metricdata.ExponentialHistogram[float64]:
		convertExponentialHistogramFloat64(data, pm)
	case metricdata.Summary:
		convertSummary(data, pm)
	}
}

func convertGaugeInt64(data metricdata.Gauge[int64], pm pmetric.Metric) {
	gauge := pm.SetEmptyGauge()
	for _, dp := range data.DataPoints {
		pdp := gauge.DataPoints().AppendEmpty()
		pdp.SetIntValue(dp.Value)
		pdp.SetTimestamp(pcommon.NewTimestampFromTime(dp.Time))
		pdp.SetStartTimestamp(pcommon.NewTimestampFromTime(dp.StartTime))
		convertDataPointAttributes(dp.Attributes, pdp.Attributes())
		convertExemplars(dp.Exemplars, pdp.Exemplars())
	}
}

func convertGaugeFloat64(data metricdata.Gauge[float64], pm pmetric.Metric) {
	gauge := pm.SetEmptyGauge()
	for _, dp := range data.DataPoints {
		pdp := gauge.DataPoints().AppendEmpty()
		pdp.SetDoubleValue(dp.Value)
		pdp.SetTimestamp(pcommon.NewTimestampFromTime(dp.Time))
		pdp.SetStartTimestamp(pcommon.NewTimestampFromTime(dp.StartTime))
		convertDataPointAttributes(dp.Attributes, pdp.Attributes())
		convertExemplarsFloat64(dp.Exemplars, pdp.Exemplars())
	}
}

func convertSumInt64(data metricdata.Sum[int64], pm pmetric.Metric) {
	sum := pm.SetEmptySum()
	sum.SetIsMonotonic(data.IsMonotonic)
	sum.SetAggregationTemporality(convertTemporality(data.Temporality))
	for _, dp := range data.DataPoints {
		pdp := sum.DataPoints().AppendEmpty()
		pdp.SetIntValue(dp.Value)
		pdp.SetTimestamp(pcommon.NewTimestampFromTime(dp.Time))
		pdp.SetStartTimestamp(pcommon.NewTimestampFromTime(dp.StartTime))
		convertDataPointAttributes(dp.Attributes, pdp.Attributes())
		convertExemplars(dp.Exemplars, pdp.Exemplars())
	}
}

func convertSumFloat64(data metricdata.Sum[float64], pm pmetric.Metric) {
	sum := pm.SetEmptySum()
	sum.SetIsMonotonic(data.IsMonotonic)
	sum.SetAggregationTemporality(convertTemporality(data.Temporality))
	for _, dp := range data.DataPoints {
		pdp := sum.DataPoints().AppendEmpty()
		pdp.SetDoubleValue(dp.Value)
		pdp.SetTimestamp(pcommon.NewTimestampFromTime(dp.Time))
		pdp.SetStartTimestamp(pcommon.NewTimestampFromTime(dp.StartTime))
		convertDataPointAttributes(dp.Attributes, pdp.Attributes())
		convertExemplarsFloat64(dp.Exemplars, pdp.Exemplars())
	}
}

func convertHistogramInt64(data metricdata.Histogram[int64], pm pmetric.Metric) {
	hist := pm.SetEmptyHistogram()
	hist.SetAggregationTemporality(convertTemporality(data.Temporality))
	for _, dp := range data.DataPoints {
		pdp := hist.DataPoints().AppendEmpty()
		pdp.SetCount(dp.Count)
		pdp.SetSum(float64(dp.Sum))
		if minValue, defined := dp.Min.Value(); defined {
			pdp.SetMin(float64(minValue))
		}
		if maxValue, defined := dp.Max.Value(); defined {
			pdp.SetMax(float64(maxValue))
		}
		pdp.SetTimestamp(pcommon.NewTimestampFromTime(dp.Time))
		pdp.SetStartTimestamp(pcommon.NewTimestampFromTime(dp.StartTime))
		pdp.ExplicitBounds().FromRaw(dp.Bounds)
		pdp.BucketCounts().FromRaw(dp.BucketCounts)
		convertDataPointAttributes(dp.Attributes, pdp.Attributes())
		convertExemplars(dp.Exemplars, pdp.Exemplars())
	}
}

func convertHistogramFloat64(data metricdata.Histogram[float64], pm pmetric.Metric) {
	hist := pm.SetEmptyHistogram()
	hist.SetAggregationTemporality(convertTemporality(data.Temporality))
	for _, dp := range data.DataPoints {
		pdp := hist.DataPoints().AppendEmpty()
		pdp.SetCount(dp.Count)
		pdp.SetSum(dp.Sum)
		if minValue, defined := dp.Min.Value(); defined {
			pdp.SetMin(minValue)
		}
		if maxValue, defined := dp.Max.Value(); defined {
			pdp.SetMax(maxValue)
		}
		pdp.SetTimestamp(pcommon.NewTimestampFromTime(dp.Time))
		pdp.SetStartTimestamp(pcommon.NewTimestampFromTime(dp.StartTime))
		pdp.ExplicitBounds().FromRaw(dp.Bounds)
		pdp.BucketCounts().FromRaw(dp.BucketCounts)
		convertDataPointAttributes(dp.Attributes, pdp.Attributes())
		convertExemplarsFloat64(dp.Exemplars, pdp.Exemplars())
	}
}

func convertExponentialHistogramInt64(data metricdata.ExponentialHistogram[int64], pm pmetric.Metric) {
	hist := pm.SetEmptyExponentialHistogram()
	hist.SetAggregationTemporality(convertTemporality(data.Temporality))
	for _, dp := range data.DataPoints {
		pdp := hist.DataPoints().AppendEmpty()
		pdp.SetCount(dp.Count)
		pdp.SetSum(float64(dp.Sum))
		if minValue, defined := dp.Min.Value(); defined {
			pdp.SetMin(float64(minValue))
		}
		if maxValue, defined := dp.Max.Value(); defined {
			pdp.SetMax(float64(maxValue))
		}
		pdp.SetScale(dp.Scale)
		pdp.SetZeroCount(dp.ZeroCount)
		pdp.SetZeroThreshold(dp.ZeroThreshold)
		pdp.SetTimestamp(pcommon.NewTimestampFromTime(dp.Time))
		pdp.SetStartTimestamp(pcommon.NewTimestampFromTime(dp.StartTime))
		pdp.Positive().SetOffset(dp.PositiveBucket.Offset)
		pdp.Positive().BucketCounts().FromRaw(dp.PositiveBucket.Counts)
		pdp.Negative().SetOffset(dp.NegativeBucket.Offset)
		pdp.Negative().BucketCounts().FromRaw(dp.NegativeBucket.Counts)
		convertDataPointAttributes(dp.Attributes, pdp.Attributes())
		convertExemplars(dp.Exemplars, pdp.Exemplars())
	}
}

func convertExponentialHistogramFloat64(data metricdata.ExponentialHistogram[float64], pm pmetric.Metric) {
	hist := pm.SetEmptyExponentialHistogram()
	hist.SetAggregationTemporality(convertTemporality(data.Temporality))
	for _, dp := range data.DataPoints {
		pdp := hist.DataPoints().AppendEmpty()
		pdp.SetCount(dp.Count)
		pdp.SetSum(dp.Sum)
		if minValue, defined := dp.Min.Value(); defined {
			pdp.SetMin(minValue)
		}
		if maxValue, defined := dp.Max.Value(); defined {
			pdp.SetMax(maxValue)
		}
		pdp.SetScale(dp.Scale)
		pdp.SetZeroCount(dp.ZeroCount)
		pdp.SetZeroThreshold(dp.ZeroThreshold)
		pdp.SetTimestamp(pcommon.NewTimestampFromTime(dp.Time))
		pdp.SetStartTimestamp(pcommon.NewTimestampFromTime(dp.StartTime))
		pdp.Positive().SetOffset(dp.PositiveBucket.Offset)
		pdp.Positive().BucketCounts().FromRaw(dp.PositiveBucket.Counts)
		pdp.Negative().SetOffset(dp.NegativeBucket.Offset)
		pdp.Negative().BucketCounts().FromRaw(dp.NegativeBucket.Counts)
		convertDataPointAttributes(dp.Attributes, pdp.Attributes())
		convertExemplarsFloat64(dp.Exemplars, pdp.Exemplars())
	}
}

func convertSummary(data metricdata.Summary, pm pmetric.Metric) {
	summary := pm.SetEmptySummary()
	for _, dp := range data.DataPoints {
		pdp := summary.DataPoints().AppendEmpty()
		pdp.SetCount(dp.Count)
		pdp.SetSum(dp.Sum)
		pdp.SetTimestamp(pcommon.NewTimestampFromTime(dp.Time))
		pdp.SetStartTimestamp(pcommon.NewTimestampFromTime(dp.StartTime))
		for _, qv := range dp.QuantileValues {
			pqv := pdp.QuantileValues().AppendEmpty()
			pqv.SetQuantile(qv.Quantile)
			pqv.SetValue(qv.Value)
		}
		convertDataPointAttributes(dp.Attributes, pdp.Attributes())
	}
}

func convertDataPointAttributes(attrs attribute.Set, pAttrs pcommon.Map) {
	for _, kv := range attrs.ToSlice() {
		convertAttribute(kv, pAttrs)
	}
}

func convertExemplars(exemplars []metricdata.Exemplar[int64], pExemplars pmetric.ExemplarSlice) {
	for _, ex := range exemplars {
		pex := pExemplars.AppendEmpty()
		pex.SetIntValue(ex.Value)
		pex.SetTimestamp(pcommon.NewTimestampFromTime(ex.Time))
		pex.SetTraceID(pcommon.TraceID(ex.TraceID))
		pex.SetSpanID(pcommon.SpanID(ex.SpanID))
		for _, kv := range ex.FilteredAttributes {
			convertAttribute(kv, pex.FilteredAttributes())
		}
	}
}

func convertExemplarsFloat64(exemplars []metricdata.Exemplar[float64], pExemplars pmetric.ExemplarSlice) {
	for _, ex := range exemplars {
		pex := pExemplars.AppendEmpty()
		pex.SetDoubleValue(ex.Value)
		pex.SetTimestamp(pcommon.NewTimestampFromTime(ex.Time))
		pex.SetTraceID(pcommon.TraceID(ex.TraceID))
		pex.SetSpanID(pcommon.SpanID(ex.SpanID))
		for _, kv := range ex.FilteredAttributes {
			convertAttribute(kv, pex.FilteredAttributes())
		}
	}
}

func convertTemporality(t metricdata.Temporality) pmetric.AggregationTemporality {
	switch t {
	case metricdata.CumulativeTemporality:
		return pmetric.AggregationTemporalityCumulative
	case metricdata.DeltaTemporality:
		return pmetric.AggregationTemporalityDelta
	default:
		return pmetric.AggregationTemporalityUnspecified
	}
}

// Ensure ConsumerExporter implements sdkmetric.Exporter
var _ sdkmetric.Exporter = (*ConsumerExporter)(nil)

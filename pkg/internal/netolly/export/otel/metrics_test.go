package otel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/attribute"

	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
	"github.com/grafana/beyla/pkg/internal/netolly/export"
)

func TestMetricAttributes(t *testing.T) {
	in := &ebpf.Record{
		NetFlowRecordT: ebpf.NetFlowRecordT{
			Id: ebpf.NetFlowId{
				Direction: 1,
				DstPort:   3210,
			},
		},
		Attrs: ebpf.RecordAttrs{
			SrcName: "srcname",
			DstName: "dstname",
			Metadata: map[string]string{
				"k8s.src.name":      "srcname",
				"k8s.src.namespace": "srcnamespace",
				"k8s.dst.name":      "dstname",
				"k8s.dst.namespace": "dstnamespace",
			},
		},
	}
	in.Id.SrcIp.In6U.U6Addr8 = [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 12, 34, 56, 78}
	in.Id.DstIp.In6U.U6Addr8 = [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 33, 22, 11, 1}

	me := &metricsExporter{attrs: export.BuildOTELAttributeGetters([]string{
		"src.address", "dst.address", "src.name", "dst_name",
		"k8s.src.name", "k8s.src_namespace", "k8s.dst.name", "k8s.dst.namespace",
	})}
	reportedAttributes := me.attributes(in)
	for _, mustContain := range []attribute.KeyValue{
		attribute.String("src.address", "12.34.56.78"),
		attribute.String("dst.address", "33.22.11.1"),
		attribute.String("src.name", "srcname"),
		attribute.String("dst.name", "dstname"),

		attribute.String("k8s.src.name", "srcname"),
		attribute.String("k8s.src.namespace", "srcnamespace"),
		attribute.String("k8s.dst.name", "dstname"),
		attribute.String("k8s.dst.namespace", "dstnamespace"),
	} {
		assert.Contains(t, reportedAttributes, mustContain)
	}

}

func TestMetricAttributes_Filter(t *testing.T) {
	in := &ebpf.Record{
		NetFlowRecordT: ebpf.NetFlowRecordT{
			Id: ebpf.NetFlowId{
				Direction: 1,
				DstPort:   3210,
			},
		},
		Attrs: ebpf.RecordAttrs{
			SrcName: "srcname",
			DstName: "dstname",
			Metadata: map[string]string{
				"k8s.src.name":      "srcname",
				"k8s.src.namespace": "srcnamespace",
				"k8s.dst.name":      "dstname",
				"k8s.dst.namespace": "dstnamespace",
			},
		},
	}
	in.Id.SrcIp.In6U.U6Addr8 = [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 12, 34, 56, 78}
	in.Id.DstIp.In6U.U6Addr8 = [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 33, 22, 11, 1}

	me := &metricsExporter{attrs: export.BuildOTELAttributeGetters([]string{
		"src.address",
		"k8s.src.name",
		"k8s.dst.name",
	})}
	reportedAttributes := me.attributes(in)
	for _, mustContain := range []attribute.KeyValue{
		attribute.String("src.address", "12.34.56.78"),
		attribute.String("k8s.src.name", "srcname"),
		attribute.String("k8s.dst.name", "dstname"),
	} {
		assert.Contains(t, reportedAttributes, mustContain)
	}
	attrNames := map[string]struct{}{}
	for _, a := range reportedAttributes {
		attrNames[string(a.Key)] = struct{}{}
	}
	for _, mustNotContain := range []string{
		"dst.address",
		"src.name",
		"dst.name",
		"k8s.src.namespace",
		"k8s.dst.namespace",
	} {
		assert.NotContains(t, attrNames, mustNotContain)
	}
}

func TestMetricsConfig_Enabled(t *testing.T) {
	assert.True(t, MetricsConfig{Metrics: &otel.MetricsConfig{
		Features: []string{otel.FeatureApplication, otel.FeatureNetwork}, CommonEndpoint: "foo"}}.Enabled())
	assert.True(t, MetricsConfig{Metrics: &otel.MetricsConfig{
		Features: []string{otel.FeatureNetwork, otel.FeatureApplication}, MetricsEndpoint: "foo"}}.Enabled())
	assert.True(t, MetricsConfig{Metrics: &otel.MetricsConfig{
		Features: []string{otel.FeatureNetwork}, Grafana: &otel.GrafanaOTLP{Submit: []string{"traces", "metrics"}, InstanceID: "33221"}}}.Enabled())
}

func TestMetricsConfig_Disabled(t *testing.T) {
	var fa = []string{otel.FeatureApplication}
	var fn = []string{otel.FeatureNetwork}
	assert.False(t, MetricsConfig{Metrics: &otel.MetricsConfig{Features: fn}}.Enabled())
	assert.False(t, MetricsConfig{Metrics: &otel.MetricsConfig{Features: fn, Grafana: &otel.GrafanaOTLP{Submit: []string{"traces"}, InstanceID: "33221"}}}.Enabled())
	assert.False(t, MetricsConfig{Metrics: &otel.MetricsConfig{Features: fn, Grafana: &otel.GrafanaOTLP{Submit: []string{"metrics"}}}}.Enabled())
	// network feature is not enabled
	assert.False(t, MetricsConfig{Metrics: &otel.MetricsConfig{CommonEndpoint: "foo"}}.Enabled())
	assert.False(t, MetricsConfig{Metrics: &otel.MetricsConfig{MetricsEndpoint: "foo", Features: fa}}.Enabled())
	assert.False(t, MetricsConfig{Metrics: &otel.MetricsConfig{Grafana: &otel.GrafanaOTLP{Submit: []string{"traces", "metrics"}, InstanceID: "33221"}}}.Enabled())
}

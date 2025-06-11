package otel

import (
	"testing"
	"time"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/netolly/ebpf"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"

	"github.com/grafana/beyla/v2/pkg/export/attributes"
	attr "github.com/grafana/beyla/v2/pkg/export/attributes/names"
	"github.com/grafana/beyla/v2/pkg/internal/pipe/global"
)

func TestMetricAttributes(t *testing.T) {
	defer restoreEnvAfterExecution()()
	in := &ebpf.Record{
		NetFlowRecordT: ebpf.NetFlowRecordT{
			Id: ebpf.NetFlowId{
				DstPort: 3210,
				SrcPort: 12345,
			},
		},
		Attrs: ebpf.RecordAttrs{
			SrcName: "srcname",
			DstName: "dstname",
			Metadata: map[attr.Name]string{
				"k8s.src.name":      "srcname",
				"k8s.src.namespace": "srcnamespace",
				"k8s.dst.name":      "dstname",
				"k8s.dst.namespace": "dstnamespace",
			},
		},
	}
	in.Id.SrcIp.In6U.U6Addr8 = [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 12, 34, 56, 78}
	in.Id.DstIp.In6U.U6Addr8 = [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 33, 22, 11, 1}

	me, err := newMetricsExporter(t.Context(),
		&global.ContextInfo{MetricAttributeGroups: attributes.GroupKubernetes},
		&NetMetricsConfig{SelectorCfg: &attributes.SelectorConfig{
			SelectionCfg: map[attributes.Section]attributes.InclusionLists{
				attributes.BeylaNetworkFlow.Section: {Include: []string{"*"}},
			},
		}, Metrics: &MetricsConfig{
			MetricsEndpoint:   "http://foo",
			Interval:          10 * time.Millisecond,
			ReportersCacheLen: 100,
			TTL:               5 * time.Minute,
			Features:          []string{FeatureNetwork, FeatureNetworkInterZone},
		}}, msg.NewQueue[[]*ebpf.Record]())
	require.NoError(t, err)

	_, reportedAttributes := me.flowBytes.ForRecord(in)
	for _, mustContain := range []attribute.KeyValue{
		attribute.String("src.address", "12.34.56.78"),
		attribute.String("dst.address", "33.22.11.1"),
		attribute.String("src.name", "srcname"),
		attribute.String("dst.name", "dstname"),
		attribute.Int("src.port", 12345),
		attribute.Int("dst.port", 3210),

		attribute.String("k8s.src.name", "srcname"),
		attribute.String("k8s.src.namespace", "srcnamespace"),
		attribute.String("k8s.dst.name", "dstname"),
		attribute.String("k8s.dst.namespace", "dstnamespace"),
	} {
		val, ok := reportedAttributes.Value(mustContain.Key)
		assert.Truef(t, ok, "expected %+v in %v", mustContain.Key, reportedAttributes)
		assert.Equal(t, mustContain.Value, val)
	}

}

func TestMetricAttributes_Filter(t *testing.T) {
	defer restoreEnvAfterExecution()()
	in := &ebpf.Record{
		NetFlowRecordT: ebpf.NetFlowRecordT{
			Id: ebpf.NetFlowId{
				DstPort: 3210,
				SrcPort: 12345,
			},
		},
		Attrs: ebpf.RecordAttrs{
			SrcName: "srcname",
			DstName: "dstname",
			Metadata: map[attr.Name]string{
				"k8s.src.name":      "srcname",
				"k8s.src.namespace": "srcnamespace",
				"k8s.dst.name":      "dstname",
				"k8s.dst.namespace": "dstnamespace",
			},
		},
	}
	in.Id.SrcIp.In6U.U6Addr8 = [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 12, 34, 56, 78}
	in.Id.DstIp.In6U.U6Addr8 = [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 33, 22, 11, 1}

	me, err := newMetricsExporter(t.Context(),
		&global.ContextInfo{MetricAttributeGroups: attributes.GroupKubernetes},
		&NetMetricsConfig{SelectorCfg: &attributes.SelectorConfig{
			SelectionCfg: map[attributes.Section]attributes.InclusionLists{
				attributes.BeylaNetworkFlow.Section: {Include: []string{
					"src.address",
					"k8s.src.name",
					"k8s.dst.name",
				}},
			},
		}, Metrics: &MetricsConfig{
			MetricsEndpoint:   "http://foo",
			Interval:          10 * time.Millisecond,
			ReportersCacheLen: 100,
			Features:          []string{FeatureNetwork, FeatureNetworkInterZone},
		}}, msg.NewQueue[[]*ebpf.Record]())
	require.NoError(t, err)

	_, reportedAttributes := me.flowBytes.ForRecord(in)
	for _, mustContain := range []attribute.KeyValue{
		attribute.String("src.address", "12.34.56.78"),
		attribute.String("k8s.src.name", "srcname"),
		attribute.String("k8s.dst.name", "dstname"),
	} {
		val, ok := reportedAttributes.Value(mustContain.Key)
		assert.True(t, ok)
		assert.Equal(t, mustContain.Value, val)
	}
	for _, mustNotContain := range []attribute.Key{
		"dst.address",
		"src.name",
		"dst.name",
		"k8s.src.namespace",
		"k8s.dst.namespace",
	} {
		assert.False(t, reportedAttributes.HasValue(mustNotContain))
	}
}

func TestNetMetricsConfig_Enabled(t *testing.T) {
	assert.True(t, NetMetricsConfig{Metrics: &MetricsConfig{
		Features: []string{FeatureApplication, FeatureNetwork}, CommonEndpoint: "foo"}}.Enabled())
	assert.True(t, NetMetricsConfig{Metrics: &MetricsConfig{
		Features: []string{FeatureNetwork, FeatureApplication}, MetricsEndpoint: "foo"}}.Enabled())
	assert.True(t, NetMetricsConfig{Metrics: &MetricsConfig{
		Features: []string{FeatureNetwork}, Grafana: &GrafanaOTLP{Submit: []string{"traces", "metrics"}, InstanceID: "33221"}}}.Enabled())
}

func TestNetMetricsConfig_Disabled(t *testing.T) {
	var fa = []string{FeatureApplication}
	var fn = []string{FeatureNetwork}
	assert.False(t, NetMetricsConfig{Metrics: &MetricsConfig{Features: fn}}.Enabled())
	assert.False(t, NetMetricsConfig{Metrics: &MetricsConfig{Features: fn, Grafana: &GrafanaOTLP{Submit: []string{"traces"}, InstanceID: "33221"}}}.Enabled())
	assert.False(t, NetMetricsConfig{Metrics: &MetricsConfig{Features: fn, Grafana: &GrafanaOTLP{Submit: []string{"metrics"}}}}.Enabled())
	// network feature is not enabled
	assert.False(t, NetMetricsConfig{Metrics: &MetricsConfig{CommonEndpoint: "foo"}}.Enabled())
	assert.False(t, NetMetricsConfig{Metrics: &MetricsConfig{MetricsEndpoint: "foo", Features: fa}}.Enabled())
	assert.False(t, NetMetricsConfig{Metrics: &MetricsConfig{Grafana: &GrafanaOTLP{Submit: []string{"traces", "metrics"}, InstanceID: "33221"}}}.Enabled())
}

func TestGetFilteredNetworkResourceAttrs(t *testing.T) {
	hostID := "test-host-id"
	attrSelector := attributes.Selection{
		attributes.BeylaNetworkFlow.Section: attributes.InclusionLists{
			Include: []string{"*"},
			Exclude: []string{"host.*"},
		},
	}

	attrs := getFilteredNetworkResourceAttrs(hostID, attrSelector)

	expectedAttrs := []string{
		"service.name",
		"service.instance.id",
		"telemetry.sdk.language",
		"telemetry.sdk.name",
		"telemetry.sdk.version",
	}

	attrMap := make(map[string]string)
	for _, attr := range attrs {
		attrMap[string(attr.Key)] = attr.Value.AsString()
	}

	for _, key := range expectedAttrs {
		_, exists := attrMap[key]
		assert.True(t, exists, "Expected attribute %s not found", key)
	}

	_, hostIDExists := attrMap["host.id"]
	assert.False(t, hostIDExists, "Host ID should be filtered out")
}

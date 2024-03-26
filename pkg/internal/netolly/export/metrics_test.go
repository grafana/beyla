package export

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/attribute"

	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
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

	me := &metricsExporter{attrs: NewAttributesFilter([]string{
		"src.address", "dst.address", "src.name", "dst.name",
		"k8s.src.name", "k8s.src.namespace", "k8s.dst.name", "k8s.dst.namespace",
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

	me := &metricsExporter{attrs: NewAttributesFilter([]string{
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

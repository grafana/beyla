package export

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAttributesMaking(t *testing.T) {
	m := map[string]interface{}{
		"AgentIP":          "172.19.0.2",
		"Bytes":            192,
		"DstAddr":          "10.244.0.3",
		"DstK8s_HostIP":    "172.19.0.2",
		"DstK8s_HostName":  "network-observability-testbed-control-plane",
		"DstK8s_Name":      "coredns-565d847f94-kbgws",
		"DstK8s_Namespace": "kube-system",
		"DstK8s_OwnerName": "coredns",
		"DstK8s_OwnerType": "Deployment",
		"DstK8s_Type":      "Pod",
		"DstMac":           "a2:0f:bf:d2:24:06",
		"DstPort":          53,
		"Duplicate":        false,
		"Etype":            2048,
		"FlowDirection":    1,
		"Interface":        "veth727426ed",
		"Packets":          2,
		"Proto":            17,
		"SrcAddr":          "10.244.0.6",
		"SrcK8s_HostIP":    "172.19.0.2",
		"SrcK8s_HostName":  "network-observability-testbed-control-plane",
		"SrcK8s_Name":      "testclient",
		"SrcK8s_Namespace": "default",
		"SrcK8s_OwnerName": "testclient",
		"SrcK8s_OwnerType": "Pod",
		"SrcK8s_Type":      "Pod",
		"SrcMac":           "9e:59:b0:c8:16:fd",
		"SrcPort":          40152,
		"TimeFlowEndMs":    1701799089328,
		"TimeFlowStartMs":  1701799089328,
		"TimeReceived":     1701799094,
	}

	attrs := attributes(m)

	assert.Equal(t, 9, len(attrs))
}

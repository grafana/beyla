package attr

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalize(t *testing.T) {
	incl := Selectors{
		"beyla_network_flow_bytes": InclusionLists{Include: []string{"foo", "bar"}},
		"some.other.metric_sum":    InclusionLists{Include: []string{"attr", "other"}},
		"tralari.tralara.total":    InclusionLists{Include: []string{"a1", "a2", "a3"}},
	}
	incl.Normalize()
	assert.Equal(t, Selectors{
		"beyla.network.flow.bytes": InclusionLists{Include: []string{"foo", "bar"}},
		"some.other.metric":        InclusionLists{Include: []string{"attr", "other"}},
		"tralari.tralara":          InclusionLists{Include: []string{"a1", "a2", "a3"}},
	}, incl)
}

func TestFor(t *testing.T) {
	incl := Selectors{
		"beyla_network_flow_bytes_total": InclusionLists{
			Include: []string{"beyla_ip", "src.*", "k8s.*"},
			Exclude: []string{"k8s_*_name", "k8s.*.type"},
		},
	}
	incl.Normalize()
	assert.Equal(t, []string{
		"beyla.ip",
		"k8s.dst.namespace",
		"k8s.dst.node.ip",
		"k8s.src.namespace",
		"k8s.src.node.ip",
		"src.address",
		"src.name",
		"src.port",
	}, incl.For(SectionBeylaNetworkFlow))
}

func TestNilDoesNotCrash(t *testing.T) {
	var aad Selectors
	assert.NotPanics(t, func() {
		aad.Normalize()
		assert.NotEmpty(t, aad.For(SectionBeylaNetworkFlow))
	})
}

func TestDefault(t *testing.T) {
	var aad Selectors
	aad.Normalize()
	assert.Equal(t, []string{
		"k8s.cluster.name",
		"k8s.dst.namespace",
		"k8s.dst.owner.name",
		"k8s.src.namespace",
		"k8s.src.owner.name",
	}, aad.For(SectionBeylaNetworkFlow))
}

package attributes

import (
	"testing"

	attr "github.com/grafana/beyla/pkg/internal/export/attributes/names"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalize(t *testing.T) {
	incl := Selection{
		"beyla_network_flow_bytes": InclusionLists{Include: []string{"foo", "bar"}},
		"some.other.metric_sum":    InclusionLists{Include: []string{"attr", "other"}},
		"tralari.tralara.total":    InclusionLists{Include: []string{"a1", "a2", "a3"}},
	}
	incl.Normalize()
	assert.Equal(t, Selection{
		"beyla.network.flow": InclusionLists{Include: []string{"foo", "bar"}},
		"some.other.metric":  InclusionLists{Include: []string{"attr", "other"}},
		"tralari.tralara":    InclusionLists{Include: []string{"a1", "a2", "a3"}},
	}, incl)
}

func TestFor(t *testing.T) {
	p, err := NewAttrSelector(GroupKubernetes, Selection{
		"beyla_network_flow_bytes_total": InclusionLists{
			Include: []string{"beyla_ip", "src.*", "k8s.*"},
			Exclude: []string{"k8s_*_name", "k8s.*.type"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		"beyla.ip",
		"k8s.dst.namespace",
		"k8s.dst.node.ip",
		"k8s.src.namespace",
		"k8s.src.node.ip",
		"src.address",
		"src.name",
		"src.port",
	}, p.For(BeylaNetworkFlow))
}

func TestFor_KubeDisabled(t *testing.T) {
	p, err := NewAttrSelector(0, Selection{
		"beyla_network_flow_bytes_total": InclusionLists{
			Include: []string{"target.instance", "beyla_ip", "src.*", "k8s.*"},
			Exclude: []string{"src.port"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		"beyla.ip",
		"src.address",
		"src.name",
	}, p.For(BeylaNetworkFlow))
}

func TestNilDoesNotCrash(t *testing.T) {
	assert.NotPanics(t, func() {
		p, err := NewAttrSelector(GroupKubernetes, nil)
		require.NoError(t, err)
		assert.NotEmpty(t, p.For(BeylaNetworkFlow))
	})
}

func TestDefault(t *testing.T) {
	p, err := NewAttrSelector(GroupKubernetes, nil)
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		"k8s.cluster.name",
		"k8s.dst.namespace",
		"k8s.dst.owner.name",
		"k8s.src.namespace",
		"k8s.src.owner.name",
	}, p.For(BeylaNetworkFlow))
}

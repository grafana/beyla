package attributes

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	attr "github.com/grafana/beyla/pkg/internal/export/attributes/names"
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
	assert.Equal(t, Sections[[]attr.Name]{
		Metric: []attr.Name{
			"beyla.ip",
			"k8s.dst.namespace",
			"k8s.dst.node.ip",
			"k8s.src.namespace",
			"k8s.src.node.ip",
			"src.address",
			"src.name",
			"src.port",
		},
		Resource: []attr.Name{},
	}, p.For(BeylaNetworkFlow))
}

func TestFor_GlobEntries(t *testing.T) {
	// include all groups just to verify that other attributes aren't anyway selected
	p, err := NewAttrSelector(GroupKubernetes, Selection{
		"*": InclusionLists{
			Include: []string{"beyla_ip"},
			Exclude: []string{"k8s_*_name"},
		},
		"beyla_network_flow_bytes_total": InclusionLists{
			Include: []string{"src.*", "k8s.*"},
			Exclude: []string{"k8s.*.type"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, Sections[[]attr.Name]{
		Metric: []attr.Name{
			"beyla.ip",
			"k8s.dst.namespace",
			"k8s.dst.node.ip",
			"k8s.src.namespace",
			"k8s.src.node.ip",
			"src.address",
			"src.name",
			"src.port",
		},
		Resource: []attr.Name{},
	}, p.For(BeylaNetworkFlow))
}

// if no include lists are defined, it takes the default arguments
func TestFor_GlobEntries_NoInclusion(t *testing.T) {
	p, err := NewAttrSelector(GroupKubernetes|GroupNetCIDR, Selection{
		"*": InclusionLists{
			Exclude: []string{"*dst*"},
		},
		"beyla_network_flow_bytes_total": InclusionLists{
			Exclude: []string{"k8s.*.namespace"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, Sections[[]attr.Name]{
		Metric: []attr.Name{
			"k8s.cluster.name",
			"k8s.src.owner.name",
			"src.cidr",
		},
		Resource: []attr.Name{},
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
	assert.Equal(t, Sections[[]attr.Name]{
		Metric: []attr.Name{
			"beyla.ip",
			"src.address",
			"src.name",
		},
		Resource: []attr.Name{},
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
	assert.Equal(t, Sections[[]attr.Name]{
		Metric: []attr.Name{
			"k8s.cluster.name",
			"k8s.dst.namespace",
			"k8s.dst.owner.name",
			"k8s.src.namespace",
			"k8s.src.owner.name",
		},
		Resource: []attr.Name{},
	}, p.For(BeylaNetworkFlow))
}

func TestTraces(t *testing.T) {
	p, err := NewAttrSelector(GroupTraces, Selection{
		"traces": InclusionLists{
			Include: []string{"db.query.text", "beyla_ip", "src.*", "k8s.*"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, Sections[[]attr.Name]{
		Metric: []attr.Name{
			"db.query.text",
		},
		Resource: []attr.Name{},
	}, p.For(Traces))
}

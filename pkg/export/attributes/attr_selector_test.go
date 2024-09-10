package attributes

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	attr "github.com/grafana/beyla/pkg/export/attributes/names"
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

func TestFor_GlobEntries(t *testing.T) {
	// include all groups just to verify that other attributes aren't anyway selected
	p, err := NewAttrSelector(GroupKubernetes, Selection{
		"*": InclusionLists{
			Include: []string{"beyla_ip"},
			// won't be excluded from the final snapshot because they are
			// re-included in the next inclusion list
			Exclude: []string{"k8s_*_type"},
		},
		"beyla_network_flow_bytes_total": InclusionLists{
			Include: []string{"src.*", "k8s.*"},
			Exclude: []string{"k8s.*.name"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		"beyla.ip",
		"k8s.dst.namespace",
		"k8s.dst.node.ip",
		"k8s.dst.owner.type",
		"k8s.dst.type",
		"k8s.src.namespace",
		"k8s.src.node.ip",
		"k8s.src.owner.type",
		"k8s.src.type",
		"src.address",
		"src.name",
		"src.port",
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
	assert.Equal(t, []attr.Name{
		"direction",
		"k8s.cluster.name",
		"k8s.src.owner.name",
		"k8s.src.owner.type",
		"src.cidr",
	}, p.For(BeylaNetworkFlow))
}

func TestFor_GlobEntries_Order(t *testing.T) {
	// verify that policies are overridden from more generic to more concrete
	p, err := NewAttrSelector(0, Selection{
		"*": InclusionLists{
			Include: []string{"*"},
		},
		"beyla_network_*": InclusionLists{
			Exclude: []string{"dst.*", "transport", "*direction", "iface"},
		},
		"beyla_network_flow_bytes_total": InclusionLists{
			Include: []string{"dst.name"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		"beyla.ip",
		"client.port",
		"dst.name",
		"server.port",
		"src.address",
		"src.name",
		"src.port",
	}, p.For(BeylaNetworkFlow))
}

func TestFor_GlobEntries_Order_Default(t *testing.T) {
	// verify that policies are overridden from more generic to more concrete
	p, err := NewAttrSelector(0, Selection{
		"*": InclusionLists{}, // assuming default set
		"http_*": InclusionLists{
			Exclude: []string{"*"},
		},
		"http_server_request_duration": InclusionLists{
			Include: []string{"url.path"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		"url.path",
	}, p.For(HTTPServerDuration))
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
		"direction",
		"k8s.cluster.name",
		"k8s.dst.namespace",
		"k8s.dst.owner.name",
		"k8s.dst.owner.type",
		"k8s.src.namespace",
		"k8s.src.owner.name",
		"k8s.src.owner.type",
	}, p.For(BeylaNetworkFlow))
}

func TestTraces(t *testing.T) {
	p, err := NewAttrSelector(GroupTraces, Selection{
		"traces": InclusionLists{
			Include: []string{"db.query.text", "beyla_ip", "src.*", "k8s.*"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		"db.query.text",
	}, p.For(Traces))
}

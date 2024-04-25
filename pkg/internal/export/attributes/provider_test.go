package attributes

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/pkg/internal/export/attributes/attr"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
)

func TestNormalize(t *testing.T) {
	incl := Selection{
		"beyla_network_flow_bytes": InclusionLists{Include: []string{"foo", "bar"}},
		"some.other.metric_sum":    InclusionLists{Include: []string{"attr", "other"}},
		"tralari.tralara.total":    InclusionLists{Include: []string{"a1", "a2", "a3"}},
	}
	incl.Normalize()
	assert.Equal(t, Selection{
		"beyla.network.flow.bytes": InclusionLists{Include: []string{"foo", "bar"}},
		"some.other.metric":        InclusionLists{Include: []string{"attr", "other"}},
		"tralari.tralara":          InclusionLists{Include: []string{"a1", "a2", "a3"}},
	}, incl)
}

func TestFor(t *testing.T) {
	p, err := NewProvider(&global.ContextInfo{K8sEnabled: true}, Selection{
		"beyla_network_flow_bytes_total": InclusionLists{
			Include: []string{"beyla_ip", "src.*", "k8s.*"},
			Exclude: []string{"k8s_*_name", "k8s.*.type"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{
		"beyla.ip",
		"k8s.dst.namespace",
		"k8s.dst.node.ip",
		"k8s.src.namespace",
		"k8s.src.node.ip",
		"src.address",
		"src.name",
		"src.port",
	}, p.For(attr.SectionBeylaNetworkFlow))
}

func TestFor_KubeDisabled(t *testing.T) {
	p, err := NewProvider(&global.ContextInfo{}, Selection{
		"beyla_network_flow_bytes_total": InclusionLists{
			Include: []string{"beyla_ip", "src.*", "k8s.*"},
			Exclude: []string{"src.port"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{
		"beyla.ip",
		"src.address",
		"src.name",
	}, p.For(attr.SectionBeylaNetworkFlow))
}

func TestNilDoesNotCrash(t *testing.T) {
	assert.NotPanics(t, func() {
		p, err := NewProvider(&global.ContextInfo{K8sEnabled: true}, nil)
		require.NoError(t, err)
		assert.NotEmpty(t, p.For(attr.SectionBeylaNetworkFlow))
	})
}

func TestDefault(t *testing.T) {
	p, err := NewProvider(&global.ContextInfo{K8sEnabled: true}, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{
		"k8s.cluster.name",
		"k8s.dst.namespace",
		"k8s.dst.owner.name",
		"k8s.src.namespace",
		"k8s.src.owner.name",
	}, p.For(attr.SectionBeylaNetworkFlow))
}

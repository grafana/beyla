package attr

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/grafana/beyla/pkg/internal/metricname"
)

func TestNormalize(t *testing.T) {
	aad := AllowedAttributesDefinition{
		"beyla_network_flow_bytes": []string{"foo", "bar"},
		"some.other.metric_sum":    []string{"attr", "other"},
		"tralari.tralara.total":    []string{"a1", "a2", "a3"},
	}
	aad.Normalize()
	assert.Equal(t, AllowedAttributesDefinition{
		"beyla.network.flow.bytes": []string{"foo", "bar"},
		"some.other.metric":        []string{"attr", "other"},
		"tralari.tralara":          []string{"a1", "a2", "a3"},
	}, aad)
}

func TestFor(t *testing.T) {
	aad := AllowedAttributesDefinition{
		"beyla.network.flow.bytes": []string{"foo", "bar"},
		"some.other.metric":        []string{"attr", "other"},
		"tralari.tralara.total":    []string{"a1", "a2", "a3"},
	}
	aad.Normalize()
	attrs := aad.For("beyla.network.flow.bytes")
	slices.Sort(attrs)
	assert.Equal(t, []string{"bar", "foo"}, attrs)
	attrs = aad.For("some.other.metric")
	slices.Sort(attrs)
	assert.Equal(t, []string{"attr", "other"}, attrs)
	attrs = aad.For("tralari.tralara")
	slices.Sort(attrs)
	assert.Equal(t, []string{"a1", "a2", "a3"}, attrs)
	assert.Empty(t, aad.For("non.existing.metric"))
}

func TestFor_GlobalDefinition(t *testing.T) {
	aad := AllowedAttributesDefinition{
		"global":                   []string{"foo", "baz"},
		"beyla.network.flow.bytes": []string{"foo", "bar"},
		"some.other.metric":        []string{"attr", "other"},
		"tralari.tralara.total":    []string{"a1", "a2", "a3"},
	}
	aad.Normalize()

	attrs := aad.For("beyla.network.flow.bytes")
	slices.Sort(attrs)
	assert.Equal(t, []string{"bar", "baz", "foo"}, attrs)
	attrs = aad.For("some.other.metric")
	slices.Sort(attrs)
	assert.Equal(t, []string{"attr", "baz", "foo", "other"}, attrs)
	attrs = aad.For("tralari.tralara")
	slices.Sort(attrs)
	assert.Equal(t, []string{"a1", "a2", "a3", "baz", "foo"}, attrs)
	attrs = aad.For("not.defined.metric")
	slices.Sort(attrs)
	assert.Equal(t, []string{"baz", "foo"}, attrs)
}

func TestNilDoesNotCrash(t *testing.T) {
	var aad AllowedAttributesDefinition
	assert.NotPanics(t, func() {
		aad.Normalize()
		assert.Empty(t, aad.For("some.metric"))
	})
}

func TestDefault(t *testing.T) {
	var aad AllowedAttributesDefinition
	aad.Normalize()
	assert.Equal(t, []string{
		"k8s.src.owner.name",
		"k8s.src.namespace",
		"k8s.dst.owner.name",
		"k8s.dst.namespace",
		"k8s.cluster.name",
	}, aad.For(metricname.NormalBeylaNetworkFlows))
}

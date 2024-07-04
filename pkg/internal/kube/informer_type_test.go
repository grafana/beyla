package kube

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInformerTypeHas(t *testing.T) {
	it := InformerTypes([]string{"Pod", "ReplicaSet", "Node"})
	require.True(t, it.Has(InformerPod))
	require.False(t, it.Has(InformerService))
	require.True(t, it.Has(InformerReplicaSet))
	require.True(t, it.Has(InformerNode))

	it = InformerTypes([]string{"Service"})
	require.False(t, it.Has(InformerPod))
	require.True(t, it.Has(InformerService))
	require.False(t, it.Has(InformerReplicaSet))
	require.False(t, it.Has(InformerNode))

	it = InformerTypes(nil)
	require.False(t, it.Has(InformerPod))
	require.False(t, it.Has(InformerService))
	require.False(t, it.Has(InformerReplicaSet))
	require.False(t, it.Has(InformerNode))
}

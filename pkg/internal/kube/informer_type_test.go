package kube

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInformerTypeHas(t *testing.T) {
	it := informerTypes([]string{"Service", "Node"})
	require.True(t, it.Has(InformerService))
	require.True(t, it.Has(InformerNode))

	it = informerTypes([]string{"Service"})
	require.True(t, it.Has(InformerService))
	require.False(t, it.Has(InformerNode))

	it = informerTypes(nil)
	require.False(t, it.Has(InformerService))
	require.False(t, it.Has(InformerNode))
}

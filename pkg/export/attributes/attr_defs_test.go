package attributes

import (
	"testing"

	attrobi "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes"
	"github.com/stretchr/testify/assert"
)

func TestEnabledGroups(t *testing.T) {
	var group attrobi.AttrGroups

	assert.False(t, group.Has(GroupPrometheus))
	assert.False(t, group.Has(GroupKubernetes))
	assert.False(t, group.Has(GroupNetCIDR))

	group.Add(GroupPrometheus)

	assert.True(t, group.Has(GroupPrometheus))
	assert.False(t, group.Has(GroupKubernetes))
	assert.False(t, group.Has(GroupNetCIDR))

	group.Add(GroupKubernetes)

	assert.True(t, group.Has(GroupPrometheus))
	assert.True(t, group.Has(GroupKubernetes))
	assert.False(t, group.Has(GroupNetCIDR))
}

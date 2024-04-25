package attributes

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnabledGroups(t *testing.T) {
	var group EnabledGroups

	assert.False(t, group.Has(EnablePrometheus))
	assert.False(t, group.Has(EnableKubernetes))

	group.Set(EnablePrometheus)

	assert.True(t, group.Has(EnablePrometheus))
	assert.False(t, group.Has(EnableKubernetes))

	group.Set(EnableKubernetes)

	assert.True(t, group.Has(EnablePrometheus))
	assert.True(t, group.Has(EnableKubernetes))
}

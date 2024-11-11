//go:build linux

package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOSCapabilities_SetClear(t *testing.T) {
	var caps OSCapabilities

	assert.Zero(t, caps[0])
	assert.Zero(t, caps[1])

	for k := range capDesc {
		assert.False(t, caps.Has(k))
		caps.Set(k)
		assert.True(t, caps.Has(k))
		caps.Clear(k)
		assert.False(t, caps.Has(k))
	}
}

func TestOSCapabilities_String(t *testing.T) {
	for k, str := range capDesc {
		assert.Equal(t, str, k.String())
	}

	assert.Equal(t, "UNKNOWN", OSCapability(99).String())
}

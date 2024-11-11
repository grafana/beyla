package svc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUID_Append(t *testing.T) {
	u := NewUID("test")
	require.NotEmpty(t, string(u))

	u1 := u.Append("a")
	u2 := u.Append("a")
	u3 := u.Append("b")

	// same operations in the same order must provide exact results
	assert.Equal(t, u1, u2)
	// different operations must provide different results
	assert.NotEqual(t, u1, u3)
}

func TestUID_AppendUint32(t *testing.T) {
	u := NewUID("test")
	require.NotEmpty(t, string(u))

	u1 := u.AppendUint32(1)
	u2 := u.AppendUint32(1)
	u3 := u.AppendUint32(2)

	// same operations in the same order must provide exact results
	assert.Equal(t, u1, u2)
	// different operations must provide different results
	assert.NotEqual(t, u1, u3)
}

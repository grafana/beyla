package svc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToString(t *testing.T) {
	assert.Equal(t, "thens/thename", (&ID{UID: UID{Namespace: "thens", Name: "thename"}}).String())
	assert.Equal(t, "thename", (&ID{UID: UID{Name: "thename"}}).String())
}

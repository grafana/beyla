package svc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToString(t *testing.T) {
	assert.Equal(t, "thens/thename", (&ID{Namespace: "thens", Name: "thename"}).String())
	assert.Equal(t, "thename", (&ID{Name: "thename"}).String())
}

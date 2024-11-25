package svc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToString(t *testing.T) {
	assert.Equal(t, "thens/thename", (&Attrs{UID: UID{Namespace: "thens", Name: "thename"}}).String())
	assert.Equal(t, "thename", (&Attrs{UID: UID{Name: "thename"}}).String())
}

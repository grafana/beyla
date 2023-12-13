package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMultiCounter(t *testing.T) {
	mc := MultiCounter[string]{}

	assert.Equal(t, 1, mc.Inc("foo"))
	assert.Equal(t, 2, mc.Inc("foo"))
	assert.Equal(t, 3, mc.Inc("foo"))

	assert.Equal(t, 1, mc.Inc("bar"))
	assert.Equal(t, 2, mc.Inc("bar"))
	assert.Equal(t, 3, mc.Inc("bar"))

	assert.Equal(t, 2, mc.Dec("foo"))
	assert.Equal(t, 1, mc.Dec("foo"))
	assert.Equal(t, 0, mc.Dec("foo"))

	assert.Equal(t, -1, mc.Dec("baz"))
	assert.Equal(t, -2, mc.Dec("baz"))
	assert.Equal(t, -3, mc.Dec("baz"))
}

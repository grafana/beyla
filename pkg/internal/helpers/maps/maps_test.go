package maps

import (
	"slices"
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

func TestMap2(t *testing.T) {
	m := Map2[string, int, string]{}

	// can't get unexisting entries
	_, ok := m.Get("foo", 1)
	assert.False(t, ok)

	// can get an added entry
	m.Put("foo", 1, "bar")
	v, ok := m.Get("foo", 1)
	assert.True(t, ok)

	// but still can't get unexisting entries at any level
	assert.Equal(t, "bar", v)
	_, ok = m.Get("foo", 2)
	assert.False(t, ok)
	_, ok = m.Get("zoo", 1)
	assert.False(t, ok)

	// can add entries at multiple tree branches
	m.Put("foo", 2, "zar")
	m.Put("tras", 1, "tris")
	v, ok = m.Get("foo", 2)
	assert.True(t, ok)
	assert.Equal(t, "zar", v)
	v, ok = m.Get("tras", 1)
	assert.True(t, ok)
	assert.Equal(t, "tris", v)

	// deleting inexisting entries have no effect"
	m.Delete("tras", 2)
	m.Delete("traca", 2)
	// only the deleted entries are not visible anymore
	m.Delete("foo", 1)
	m.Delete("tras", 1)

	v, ok = m.Get("foo", 2)
	assert.True(t, ok)
	assert.Equal(t, "zar", v)
	_, ok = m.Get("tras", 1)
	assert.False(t, ok)
	_, ok = m.Get("foo", 1)
	assert.False(t, ok)
}

func TestMap2_DeleteAll(t *testing.T) {
	m := Map2[int, int, int]{}
	m.Put(1, 1, 11)
	m.Put(1, 2, 12)
	m.Put(2, 1, 21)
	m.Put(2, 2, 22)
	m.DeleteAll(1)

	// first-level entries are removed
	_, ok := m.Get(1, 1)
	assert.False(t, ok)
	_, ok = m.Get(1, 2)
	assert.False(t, ok)

	// other first-level entries are kept
	v, ok := m.Get(2, 1)
	assert.True(t, ok)
	assert.Equal(t, 21, v)
	v, ok = m.Get(2, 2)
	assert.True(t, ok)
	assert.Equal(t, 22, v)
}

func TestSliceToSet(t *testing.T) {
	assert.Equal(t, map[int]struct{}{1: {}, 2: {}, 3: {}},
		SliceToSet([]int{2, 3, 1, 1, 1, 2, 3}))
}

func TestSetToSlice(t *testing.T) {
	slice := SetToSlice(map[int]struct{}{1: {}, 2: {}, 3: {}})
	slices.Sort(slice)
	assert.Equal(t, []int{1, 2, 3}, slice)
}

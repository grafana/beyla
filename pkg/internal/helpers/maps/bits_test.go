package maps

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type key int

var mapper = map[key]Bits{1: 0b0001, 2: 0b0010, 3: 0b0100, 4: 0b1000}

func TestBits_Full(t *testing.T) {
	bits := MappedBits([]key{1, 2, 3, 4}, mapper)
	assert.True(t, bits.Has(0b0001))
	assert.True(t, bits.Has(0b0010))
	assert.True(t, bits.Has(0b0100))
	assert.True(t, bits.Has(0b1000))
}

func TestBits_Empty(t *testing.T) {
	bits := MappedBits(nil, mapper)
	assert.False(t, bits.Has(0b0001))
	assert.False(t, bits.Has(0b0010))
	assert.False(t, bits.Has(0b0100))
	assert.False(t, bits.Has(0b1000))
}

func TestBits_IgnoreUnknownEnums(t *testing.T) {
	bits := MappedBits([]key{1, 2, 3, 40}, mapper)
	assert.True(t, bits.Has(0b0001))
	assert.True(t, bits.Has(0b0010))
	assert.True(t, bits.Has(0b0100))
	assert.False(t, bits.Has(0b1000))
}

func TestBits_Transform(t *testing.T) {
	bits := MappedBits([]key{10, 30, 8910}, mapper,
		WithTransform(func(k key) key { return k / 10 }))
	assert.True(t, bits.Has(0b0001))
	assert.False(t, bits.Has(0b0010))
	assert.True(t, bits.Has(0b0100))
	assert.False(t, bits.Has(0b1000))
	assert.False(t, bits.Has(0xb10000)) // key non-existing i the mappers
}

//go:build linux

package generictracer

import (
	"testing"

	ebpfcommon "github.com/grafana/beyla/pkg/internal/ebpf/common"
	"github.com/stretchr/testify/assert"
)

func TestBitPositionCalculation(t *testing.T) {
	for _, v := range [][4]uint32{
		{0, 1, 0, 1},
		{0, 2, 0, 2},
		{0, 65, 1, 1},
		{0, 66, 1, 2},
		{0, primeHash, 0, 0},
		{0, primeHash + 1, 0, 1},
	} {
		k := makeKey(v[0], v[1])
		segment, bit := pidSegmentBit(k)
		assert.Equal(t, segment, v[2])
		assert.Equal(t, bit, v[3])
	}
}

func makeKey(first, second uint32) uint64 {
	return uint64((uint64(first) << 32) | uint64(second))
}

type dummyCloser struct {
	closed bool
}

func (d *dummyCloser) Close() error {
	d.closed = true
	return nil
}

func TestInstrumetedLibsT(t *testing.T) {
	libs := make(ebpfcommon.InstrumentedLibsT)

	const id = uint64(10)

	assert.Nil(t, libs.Find(id))

	module := libs.At(id)

	assert.NotNil(t, module)

	closer := &dummyCloser{closed: false}
	module.Closers = append(module.Closers, closer)

	removeRef := func(id uint64) *ebpfcommon.LibModule {
		m, _ := libs.RemoveRef(id)
		return m
	}

	assert.NotNil(t, libs.Find(id))

	assert.Equal(t, uint64(0), module.References)

	assert.Equal(t, module, libs.AddRef(id))
	assert.Equal(t, uint64(1), module.References)

	assert.Equal(t, module, libs.AddRef(id))
	assert.Equal(t, uint64(2), module.References)

	assert.Equal(t, module, libs.Find(id))

	assert.Equal(t, module, removeRef(id))
	assert.Equal(t, uint64(1), module.References)
	assert.False(t, closer.closed)

	assert.Equal(t, module, removeRef(id))
	assert.Equal(t, uint64(0), module.References)
	assert.True(t, closer.closed)

	assert.Nil(t, libs.Find(id))
}

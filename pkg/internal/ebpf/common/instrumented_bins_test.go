package ebpfcommon

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type dummyCloser struct {
	closed bool
}

func (d *dummyCloser) Close() error {
	d.closed = true
	return nil
}

func TestInstrumetedLibsT(t *testing.T) {
	bins := make(InstrumentedBins)

	const id = uint64(10)

	assert.Nil(t, bins.Find(id))

	module := bins.At(id)

	assert.NotNil(t, module)

	closer := &dummyCloser{closed: false}
	module.Closers = append(module.Closers, closer)

	removeRef := func(id uint64) *BinModule {
		m, _ := bins.RemoveRef(id)
		return m
	}

	assert.NotNil(t, bins.Find(id))

	assert.Equal(t, uint64(0), module.References)

	assert.Equal(t, module, bins.AddRef(id))
	assert.Equal(t, uint64(1), module.References)

	assert.Equal(t, module, bins.AddRef(id))
	assert.Equal(t, uint64(2), module.References)

	assert.Equal(t, module, bins.Find(id))

	assert.Equal(t, module, removeRef(id))
	assert.Equal(t, uint64(1), module.References)
	assert.False(t, closer.closed)

	assert.Equal(t, module, removeRef(id))
	assert.Equal(t, uint64(0), module.References)
	assert.True(t, closer.closed)

	assert.Nil(t, bins.Find(id))
}

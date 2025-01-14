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
	libs := make(InstrumentedLibsT)

	const id = uint64(10)

	assert.Nil(t, libs.Find(id))

	module := libs.At(id)

	assert.NotNil(t, module)

	closer := &dummyCloser{closed: false}
	module.Closers = append(module.Closers, closer)

	removeRef := func(id uint64) *LibModule {
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

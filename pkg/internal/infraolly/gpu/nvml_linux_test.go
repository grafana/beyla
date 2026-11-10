//go:build linux && beyla_nvml

package gpu

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

// The NVML structs are passed by pointer to the C library, so their
// layout must match the one of nvml.h
func TestNVMLStructLayouts(t *testing.T) {
	assert.EqualValues(t, 8, unsafe.Sizeof(nvmlUtilization{}))
	assert.EqualValues(t, 24, unsafe.Sizeof(nvmlMemory{}))
	assert.EqualValues(t, 68, unsafe.Sizeof(nvmlPciInfo{}))
	assert.EqualValues(t, 36, unsafe.Offsetof(nvmlPciInfo{}.BusID))
	assert.EqualValues(t, 24, unsafe.Sizeof(nvmlProcessInfo{}))
	assert.EqualValues(t, 8, unsafe.Offsetof(nvmlProcessInfo{}.UsedGPUMemory))
	assert.EqualValues(t, 32, unsafe.Sizeof(nvmlProcessUtilizationSample{}))
	assert.EqualValues(t, 16, unsafe.Offsetof(nvmlProcessUtilizationSample{}.SmUtil))
}

func TestCString(t *testing.T) {
	assert.Equal(t, "NVIDIA H100", cString([]byte("NVIDIA H100\x00garbage")))
	assert.Equal(t, "abc", cString([]byte("abc")))
}

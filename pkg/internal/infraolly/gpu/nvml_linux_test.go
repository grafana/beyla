//go:build linux && beyla_nvml

package gpu

import (
	"fmt"
	"math"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestDiscoverNVIDIAUUIDErrors(t *testing.T) {
	for _, tc := range []struct {
		name     string
		failUUID map[uintptr]bool
		wantIDs  []string
	}{
		{name: "all succeed", wantIDs: []string{"GPU-0", "GPU-1", "GPU-2"}},
		{name: "partial failure", failUUID: map[uintptr]bool{1: true}, wantIDs: []string{"GPU-0", "GPU-2"}},
		{name: "all fail", failUUID: map[uintptr]bool{0: true, 1: true, 2: true}, wantIDs: []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nvmlMu.Lock()
			previousAPI, previousLoaded := nvml, nvmlLoaded
			nvml = &nvmlAPI{
				errorString: func(nvmlReturn) string { return "UUID unavailable" },
				deviceGetCount: func(count *uint32) nvmlReturn {
					*count = 3
					return nvmlSuccess
				},
				deviceGetHandleByIndex: func(index uint32, handle *uintptr) nvmlReturn {
					*handle = uintptr(index)
					return nvmlSuccess
				},
				deviceGetName: func(uintptr, *byte, uint32) nvmlReturn { return nvmlSuccess },
				deviceGetUUID: func(handle uintptr, uuid *byte, size uint32) nvmlReturn {
					if tc.failUUID[handle] {
						return nvmlErrorNotFound
					}
					copy(unsafe.Slice(uuid, int(size)), fmt.Sprintf("GPU-%d", handle))
					return nvmlSuccess
				},
			}
			nvmlLoaded = true
			nvmlMu.Unlock()
			t.Cleanup(func() {
				nvmlMu.Lock()
				defer nvmlMu.Unlock()
				nvml, nvmlLoaded = previousAPI, previousLoaded
			})

			devices, err := discoverNVIDIA()
			if len(tc.failUUID) == 0 {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				for index := range tc.failUUID {
					assert.Contains(t, err.Error(), fmt.Sprintf("nvmlDeviceGetUUID(%d): UUID unavailable", index))
				}
			}
			ids := make([]string, 0, len(devices))
			for _, device := range devices {
				ids = append(ids, device.Info().ID)
			}
			assert.Equal(t, tc.wantIDs, ids)
		})
	}
}

func TestNVMLIntegerReadings(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value uint64
		want  int64
	}{
		{name: "zero"},
		{name: "normal", value: 1024, want: 1024},
		{name: "maximum signed", value: math.MaxInt64, want: math.MaxInt64},
		{name: "overflow", value: uint64(math.MaxInt64) + 1},
		{name: "unavailable", value: math.MaxUint64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &nvidiaDevice{api: &nvmlAPI{
				deviceGetMemoryInfo: func(_ uintptr, memory *nvmlMemory) nvmlReturn {
					memory.Total, memory.Used = tc.value, tc.value
					return nvmlSuccess
				},
				deviceGetTotalEccErrors: func(_ uintptr, _, _ uint32, count *uint64) nvmlReturn {
					*count = tc.value
					return nvmlSuccess
				},
				deviceGetComputeRunningProcesses: func(_ uintptr, count *uint32, info *nvmlProcessInfo) nvmlReturn {
					*count = 1
					*info = nvmlProcessInfo{PID: 123, UsedGPUMemory: tc.value}
					return nvmlSuccess
				},
			}}
			sample, err := d.Sample()
			require.NoError(t, err)
			require.NotNil(t, sample.MemoryLimitBytes)
			require.NotNil(t, sample.MemoryUsedBytes)
			assert.Equal(t, tc.want, *sample.MemoryLimitBytes)
			assert.Equal(t, tc.want, *sample.MemoryUsedBytes)
			assert.Equal(t, []ErrorCount{
				{Type: "corrected", Count: tc.want},
				{Type: "uncorrected", Count: tc.want},
			}, sample.Errors)

			processes, err := d.Processes()
			require.NoError(t, err)
			require.Len(t, processes, 1)
			assert.Equal(t, uint32(123), processes[0].PID)
			require.NotNil(t, processes[0].MemoryBytes)
			assert.Equal(t, tc.want, *processes[0].MemoryBytes)
		})
	}
}

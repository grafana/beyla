//go:build linux && beyla_nvml

package gpu

import (
	"errors"
	"fmt"
	"sync"

	"github.com/ebitengine/purego"
)

// NVML is loaded at runtime through purego, so CGO is not required. However, purego
// makes the binary dynamically linked against the system libc, which is why this backend
// is only built with the beyla_nvml build tag, and requires a glibc-based container image.
// Reference: https://docs.nvidia.com/deploy/nvml-api/index.html

type nvmlReturn int32

const (
	nvmlSuccess               nvmlReturn = 0
	nvmlErrorNotFound         nvmlReturn = 6
	nvmlErrorInsufficientSize nvmlReturn = 7
)

const (
	nvmlTemperatureGPU      = 0
	nvmlClockGraphics       = 0
	nvmlClockSM             = 1
	nvmlClockMem            = 2
	nvmlMemoryErrCorrected  = 0
	nvmlMemoryErrUncorrect  = 1
	nvmlVolatileECC         = 0
	nvmlDeviceNameBufSize   = 96
	nvmlDeviceUUIDBufSize   = 96
	nvmlDeviceBusIDBufSize  = 32
	nvmlDeviceBusIDLegacy   = 16
	nvmlMaxProcessesDefault = 64
)

type nvmlUtilization struct {
	GPU    uint32
	Memory uint32
}

type nvmlMemory struct {
	Total uint64
	Free  uint64
	Used  uint64
}

// nvmlPciInfo matches nvmlPciInfo_t as returned by nvmlDeviceGetPciInfo_v3
type nvmlPciInfo struct {
	BusIDLegacy    [nvmlDeviceBusIDLegacy]byte
	Domain         uint32
	Bus            uint32
	Device         uint32
	PciDeviceID    uint32
	PciSubSystemID uint32
	BusID          [nvmlDeviceBusIDBufSize]byte
}

// nvmlProcessInfo matches nvmlProcessInfo_t (v2 layout) as returned by
// nvmlDeviceGetComputeRunningProcesses_v2 and _v3
type nvmlProcessInfo struct {
	PID               uint32
	UsedGPUMemory     uint64
	GPUInstanceID     uint32
	ComputeInstanceID uint32
}

type nvmlProcessUtilizationSample struct {
	PID       uint32
	TimeStamp uint64
	SmUtil    uint32
	MemUtil   uint32
	EncUtil   uint32
	DecUtil   uint32
}

type nvmlAPI struct {
	init                   func() nvmlReturn
	shutdown               func() nvmlReturn
	errorString            func(nvmlReturn) string
	deviceGetCount         func(*uint32) nvmlReturn
	deviceGetHandleByIndex func(uint32, *uintptr) nvmlReturn
	deviceGetName          func(uintptr, *byte, uint32) nvmlReturn
	deviceGetUUID          func(uintptr, *byte, uint32) nvmlReturn
	deviceGetPciInfo       func(uintptr, *nvmlPciInfo) nvmlReturn

	deviceGetUtilizationRates       func(uintptr, *nvmlUtilization) nvmlReturn
	deviceGetEncoderUtilization     func(uintptr, *uint32, *uint32) nvmlReturn
	deviceGetDecoderUtilization     func(uintptr, *uint32, *uint32) nvmlReturn
	deviceGetMemoryInfo             func(uintptr, *nvmlMemory) nvmlReturn
	deviceGetTemperature            func(uintptr, uint32, *uint32) nvmlReturn
	deviceGetFanSpeed               func(uintptr, *uint32) nvmlReturn
	deviceGetPowerUsage             func(uintptr, *uint32) nvmlReturn
	deviceGetEnforcedPowerLimit     func(uintptr, *uint32) nvmlReturn
	deviceGetTotalEnergyConsumption func(uintptr, *uint64) nvmlReturn
	deviceGetClockInfo              func(uintptr, uint32, *uint32) nvmlReturn
	deviceGetTotalEccErrors         func(uintptr, uint32, uint32, *uint64) nvmlReturn
	deviceGetPcieReplayCounter      func(uintptr, *uint32) nvmlReturn

	deviceGetComputeRunningProcesses func(uintptr, *uint32, *nvmlProcessInfo) nvmlReturn
	deviceGetProcessUtilization      func(uintptr, *nvmlProcessUtilizationSample, *uint32, uint64) nvmlReturn
}

var (
	nvmlMu     sync.Mutex
	nvml       *nvmlAPI
	nvmlLoaded bool
)

func loadNVML() (*nvmlAPI, error) {
	var lib uintptr
	var err error
	for _, name := range []string{"libnvidia-ml.so.1", "libnvidia-ml.so"} {
		if lib, err = purego.Dlopen(name, purego.RTLD_NOW|purego.RTLD_GLOBAL); err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("loading NVML library: %w", err)
	}
	api := &nvmlAPI{}
	// required symbols. The versioned names are tried first
	var missing []string
	for _, sym := range []struct {
		fn    any
		names []string
	}{
		{&api.init, []string{"nvmlInit_v2", "nvmlInit"}},
		{&api.shutdown, []string{"nvmlShutdown"}},
		{&api.errorString, []string{"nvmlErrorString"}},
		{&api.deviceGetCount, []string{"nvmlDeviceGetCount_v2", "nvmlDeviceGetCount"}},
		{&api.deviceGetHandleByIndex, []string{"nvmlDeviceGetHandleByIndex_v2", "nvmlDeviceGetHandleByIndex"}},
		{&api.deviceGetName, []string{"nvmlDeviceGetName"}},
		{&api.deviceGetUUID, []string{"nvmlDeviceGetUUID"}},
	} {
		if !bindNVML(lib, sym.fn, sym.names...) {
			missing = append(missing, sym.names[0])
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("NVML library misses required symbols: %v", missing)
	}
	// optional symbols: metrics are omitted if they are not available in the installed driver
	bindNVML(lib, &api.deviceGetPciInfo, "nvmlDeviceGetPciInfo_v3", "nvmlDeviceGetPciInfo_v2")
	bindNVML(lib, &api.deviceGetUtilizationRates, "nvmlDeviceGetUtilizationRates")
	bindNVML(lib, &api.deviceGetEncoderUtilization, "nvmlDeviceGetEncoderUtilization")
	bindNVML(lib, &api.deviceGetDecoderUtilization, "nvmlDeviceGetDecoderUtilization")
	bindNVML(lib, &api.deviceGetMemoryInfo, "nvmlDeviceGetMemoryInfo")
	bindNVML(lib, &api.deviceGetTemperature, "nvmlDeviceGetTemperature")
	bindNVML(lib, &api.deviceGetFanSpeed, "nvmlDeviceGetFanSpeed")
	bindNVML(lib, &api.deviceGetPowerUsage, "nvmlDeviceGetPowerUsage")
	bindNVML(lib, &api.deviceGetEnforcedPowerLimit, "nvmlDeviceGetEnforcedPowerLimit")
	bindNVML(lib, &api.deviceGetTotalEnergyConsumption, "nvmlDeviceGetTotalEnergyConsumption")
	bindNVML(lib, &api.deviceGetClockInfo, "nvmlDeviceGetClockInfo")
	bindNVML(lib, &api.deviceGetTotalEccErrors, "nvmlDeviceGetTotalEccErrors")
	bindNVML(lib, &api.deviceGetPcieReplayCounter, "nvmlDeviceGetPcieReplayCounter")
	bindNVML(lib, &api.deviceGetComputeRunningProcesses,
		"nvmlDeviceGetComputeRunningProcesses_v3", "nvmlDeviceGetComputeRunningProcesses_v2")
	bindNVML(lib, &api.deviceGetProcessUtilization, "nvmlDeviceGetProcessUtilization")
	return api, nil
}

// bindNVML registers fn with the first symbol from names that is present in the library
func bindNVML(lib uintptr, fn any, names ...string) bool {
	for _, name := range names {
		if _, err := purego.Dlsym(lib, name); err == nil {
			purego.RegisterLibFunc(fn, lib, name)
			return true
		}
	}
	return false
}

func initNVML() (*nvmlAPI, error) {
	nvmlMu.Lock()
	defer nvmlMu.Unlock()
	if nvmlLoaded {
		return nvml, nil
	}
	api, err := loadNVML()
	if err != nil {
		return nil, err
	}
	if ret := api.init(); ret != nvmlSuccess {
		return nil, fmt.Errorf("nvmlInit: %s", api.errorString(ret))
	}
	nvml, nvmlLoaded = api, true
	return nvml, nil
}

func shutdownNVIDIA() {
	nvmlMu.Lock()
	defer nvmlMu.Unlock()
	if nvmlLoaded {
		nvml.shutdown()
		nvml, nvmlLoaded = nil, false
	}
}

func discoverNVIDIA() ([]Device, error) {
	api, err := initNVML()
	if err != nil {
		return nil, err
	}
	var count uint32
	if ret := api.deviceGetCount(&count); ret != nvmlSuccess {
		return nil, fmt.Errorf("nvmlDeviceGetCount: %s", api.errorString(ret))
	}
	devices := make([]Device, 0, count)
	var errs []error
	for i := uint32(0); i < count; i++ {
		var handle uintptr
		if ret := api.deviceGetHandleByIndex(i, &handle); ret != nvmlSuccess {
			errs = append(errs, fmt.Errorf("nvmlDeviceGetHandleByIndex(%d): %s", i, api.errorString(ret)))
			continue
		}
		var name [nvmlDeviceNameBufSize]byte
		var uuid [nvmlDeviceUUIDBufSize]byte
		api.deviceGetName(handle, &name[0], uint32(len(name)))
		api.deviceGetUUID(handle, &uuid[0], uint32(len(uuid)))
		d := &nvidiaDevice{api: api, handle: handle, info: DeviceInfo{
			Vendor: VendorNVIDIA,
			ID:     cString(uuid[:]),
			Name:   cString(name[:]),
		}}
		if api.deviceGetPciInfo != nil {
			var pci nvmlPciInfo
			if api.deviceGetPciInfo(handle, &pci) == nvmlSuccess {
				d.info.PCIAddress = normalizeNVMLBusID(cString(pci.BusID[:]))
			}
		}
		devices = append(devices, d)
	}
	return devices, errors.Join(errs...)
}

type nvidiaDevice struct {
	api    *nvmlAPI
	handle uintptr
	info   DeviceInfo

	mu sync.Mutex
	// lastUtilTimestamp is the newest process utilization sample timestamp already processed
	lastUtilTimestamp uint64
}

func (d *nvidiaDevice) Info() DeviceInfo { return d.info }

func (d *nvidiaDevice) Close() {}

func (d *nvidiaDevice) Sample() (*Sample, error) {
	api, h := d.api, d.handle
	s := &Sample{
		// NVML reports the fan speed as a percentage of the maximum speed, not in RPM
		FanSpeedRatio: nvmlUint32(api.deviceGetFanSpeed, h, 1.0/100),
		// power is reported in milliwatts and energy in millijoules
		PowerWatts:      nvmlUint32(api.deviceGetPowerUsage, h, 1.0/1000),
		PowerLimitWatts: nvmlUint32(api.deviceGetEnforcedPowerLimit, h, 1.0/1000),
	}
	var u64 uint64
	if api.deviceGetTotalEnergyConsumption != nil && api.deviceGetTotalEnergyConsumption(h, &u64) == nvmlSuccess {
		s.EnergyJoules = ptr(float64(u64) / 1000)
	}
	var temp uint32
	if api.deviceGetTemperature != nil && api.deviceGetTemperature(h, nvmlTemperatureGPU, &temp) == nvmlSuccess {
		s.Temperatures = []Temperature{{Location: "die", Celsius: float64(temp)}}
	}
	var mem nvmlMemory
	if api.deviceGetMemoryInfo != nil && api.deviceGetMemoryInfo(h, &mem) == nvmlSuccess {
		s.MemoryLimitBytes = ptr(int64(mem.Total))
		s.MemoryUsedBytes = ptr(int64(mem.Used))
	}
	d.sampleUtilization(s)
	d.sampleClocks(s)
	d.sampleErrors(s)
	return s, nil
}

func (d *nvidiaDevice) sampleUtilization(s *Sample) {
	api, h := d.api, d.handle
	var util nvmlUtilization
	if api.deviceGetUtilizationRates != nil && api.deviceGetUtilizationRates(h, &util) == nvmlSuccess {
		s.Utilization = ptr(float64(util.GPU) / 100)
		s.MemoryControllerUtilization = ptr(float64(util.Memory) / 100)
	}
	s.EncoderUtilization = nvmlCodecUtilization(api.deviceGetEncoderUtilization, h)
	s.DecoderUtilization = nvmlCodecUtilization(api.deviceGetDecoderUtilization, h)
}

func (d *nvidiaDevice) sampleClocks(s *Sample) {
	if d.api.deviceGetClockInfo == nil {
		return
	}
	var mhz uint32
	for _, c := range []struct {
		clockType uint32
		domain    string
	}{{nvmlClockGraphics, "graphics"}, {nvmlClockSM, "sm"}, {nvmlClockMem, "memory"}} {
		if d.api.deviceGetClockInfo(d.handle, c.clockType, &mhz) == nvmlSuccess {
			s.Clocks = append(s.Clocks, Clock{Domain: c.domain, Hertz: float64(mhz) * 1e6})
		}
	}
}

func (d *nvidiaDevice) sampleErrors(s *Sample) {
	api, h := d.api, d.handle
	if api.deviceGetTotalEccErrors != nil {
		var count uint64
		if api.deviceGetTotalEccErrors(h, nvmlMemoryErrCorrected, nvmlVolatileECC, &count) == nvmlSuccess {
			s.Errors = append(s.Errors, ErrorCount{Type: "corrected", Count: int64(count)})
		}
		if api.deviceGetTotalEccErrors(h, nvmlMemoryErrUncorrect, nvmlVolatileECC, &count) == nvmlSuccess {
			s.Errors = append(s.Errors, ErrorCount{Type: "uncorrected", Count: int64(count)})
		}
	}
	var replays uint32
	if api.deviceGetPcieReplayCounter != nil && api.deviceGetPcieReplayCounter(h, &replays) == nvmlSuccess {
		s.Errors = append(s.Errors, ErrorCount{Type: "pcie_replay", Count: int64(replays)})
	}
}

// nvmlUint32 invokes an optional NVML getter and returns its scaled value, or nil if it's not available
func nvmlUint32(fn func(uintptr, *uint32) nvmlReturn, h uintptr, scale float64) *float64 {
	var v uint32
	if fn == nil || fn(h, &v) != nvmlSuccess {
		return nil
	}
	return ptr(float64(v) * scale)
}

// nvmlCodecUtilization invokes an optional encoder/decoder utilization getter, in the 0..1 range
func nvmlCodecUtilization(fn func(uintptr, *uint32, *uint32) nvmlReturn, h uintptr) *float64 {
	var util, samplingPeriodUs uint32
	if fn == nil || fn(h, &util, &samplingPeriodUs) != nvmlSuccess {
		return nil
	}
	return ptr(float64(util) / 100)
}

// Processes returns the GPU memory and the average SM utilization, since the previous
// invocation, of the compute processes running in the device
func (d *nvidiaDevice) Processes() ([]ProcessUsage, error) {
	api := d.api
	if api.deviceGetComputeRunningProcesses == nil {
		return nil, nil
	}
	infos := make([]nvmlProcessInfo, nvmlMaxProcessesDefault)
	count := uint32(len(infos))
	ret := api.deviceGetComputeRunningProcesses(d.handle, &count, &infos[0])
	if ret == nvmlErrorInsufficientSize {
		// processes might have been started between both invocations, so leave some margin
		infos = make([]nvmlProcessInfo, count*2)
		count = uint32(len(infos))
		ret = api.deviceGetComputeRunningProcesses(d.handle, &count, &infos[0])
	}
	if ret != nvmlSuccess {
		return nil, fmt.Errorf("nvmlDeviceGetComputeRunningProcesses: %s", api.errorString(ret))
	}
	procs := make([]ProcessUsage, 0, count)
	for _, info := range infos[:count] {
		procs = append(procs, ProcessUsage{PID: info.PID, MemoryBytes: ptr(int64(info.UsedGPUMemory))})
	}
	if utils, ok := d.processUtilization(); ok {
		for i := range procs {
			procs[i].Utilization = ptr(utils[procs[i].PID])
		}
	}
	return procs, nil
}

// processUtilization returns the average SM utilization of each process, in the 0..1 range,
// from the samples taken since the previous invocation
func (d *nvidiaDevice) processUtilization() (map[uint32]float64, bool) {
	api := d.api
	if api.deviceGetProcessUtilization == nil {
		return nil, false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var count uint32
	ret := api.deviceGetProcessUtilization(d.handle, nil, &count, d.lastUtilTimestamp)
	switch ret {
	case nvmlErrorNotFound:
		// no process used the GPU since the last invocation
		return map[uint32]float64{}, true
	case nvmlErrorInsufficientSize, nvmlSuccess:
	default:
		return nil, false
	}
	if count == 0 {
		return map[uint32]float64{}, true
	}
	samples := make([]nvmlProcessUtilizationSample, count)
	ret = api.deviceGetProcessUtilization(d.handle, &samples[0], &count, d.lastUtilTimestamp)
	if ret == nvmlErrorNotFound {
		return map[uint32]float64{}, true
	}
	if ret != nvmlSuccess {
		return nil, false
	}
	sums := map[uint32]float64{}
	counts := map[uint32]int{}
	for _, smp := range samples[:count] {
		sums[smp.PID] += float64(smp.SmUtil) / 100
		counts[smp.PID]++
		d.lastUtilTimestamp = max(d.lastUtilTimestamp, smp.TimeStamp)
	}
	for pid := range sums {
		sums[pid] /= float64(counts[pid])
	}
	return sums, true
}

func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

package gpu

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// amdDevice reads AMD GPU telemetry from the amdgpu driver sysfs and hwmon entries.
// See https://docs.kernel.org/gpu/amdgpu/thermal.html and https://docs.kernel.org/gpu/amdgpu/driver-misc.html
type amdDevice struct {
	info DeviceInfo
	card drmCard
}

func newAMDDevice(card drmCard) *amdDevice {
	name := readString(filepath.Join(card.devPath, "product_name"))
	if name == "" {
		name = "AMD GPU " + card.pciID
	}
	id := readString(filepath.Join(card.devPath, "unique_id"))
	if id == "" {
		id = card.pciAddress
	}
	return &amdDevice{
		info: DeviceInfo{Vendor: VendorAMD, ID: id, Name: name, PCIAddress: card.pciAddress},
		card: card,
	}
}

func (d *amdDevice) Info() DeviceInfo { return d.info }

func (d *amdDevice) Close() {}

func (d *amdDevice) Sample() (*Sample, error) {
	dev := d.card.devPath
	s := &Sample{
		Utilization:                 readRatioPercent(filepath.Join(dev, "gpu_busy_percent")),
		MemoryControllerUtilization: readRatioPercent(filepath.Join(dev, "mem_busy_percent")),
	}
	if v, err := readInt(filepath.Join(dev, "mem_info_vram_total")); err == nil {
		s.MemoryLimitBytes = &v
	}
	if v, err := readInt(filepath.Join(dev, "mem_info_vram_used")); err == nil {
		s.MemoryUsedBytes = &v
	}
	if hw := d.card.hwmonPath; hw != "" {
		s.Temperatures = hwmonTemperatures(hw)
		// newer kernels and APUs only expose the instantaneous power1_input
		s.PowerWatts = readMicro(filepath.Join(hw, "power1_average"), filepath.Join(hw, "power1_input"))
		s.PowerLimitWatts = readMicro(filepath.Join(hw, "power1_cap"))
		s.EnergyJoules = readMicro(filepath.Join(hw, "energy1_input"))
		if v, err := readInt(filepath.Join(hw, "fan1_input")); err == nil {
			s.FanSpeedRPM = ptr(float64(v))
		}
		s.Clocks = amdClocks(hw)
	}
	s.Errors = amdRASErrors(dev)
	return s, nil
}

// amdClocks reads the freqN_input hwmon entries, which amdgpu labels as sclk (graphics) and mclk (memory)
func amdClocks(hwmonPath string) []Clock {
	inputs, _ := filepath.Glob(filepath.Join(hwmonPath, "freq*_input"))
	var clocks []Clock
	for _, input := range inputs {
		hz, err := readInt(input)
		if err != nil {
			continue
		}
		domain := readString(strings.TrimSuffix(input, "_input") + "_label")
		switch domain {
		case "sclk":
			domain = "graphics"
		case "mclk":
			domain = "memory"
		}
		if domain == "" {
			continue
		}
		clocks = append(clocks, Clock{Domain: domain, Hertz: float64(hz)})
	}
	return clocks
}

// amdRASErrors sums the corrected and uncorrected error counters from the
// ras/<block>_err_count files, whose content looks like "ue: 0\nce: 1"
func amdRASErrors(devPath string) []ErrorCount {
	files, _ := filepath.Glob(filepath.Join(devPath, "ras", "*_err_count"))
	if len(files) == 0 {
		return nil
	}
	var ce, ue int64
	found := false
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			key, val, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			n, err := strconv.ParseInt(strings.TrimSpace(val), 10, 64)
			if err != nil {
				continue
			}
			switch strings.TrimSpace(key) {
			case "ce":
				ce += n
				found = true
			case "ue":
				ue += n
				found = true
			}
		}
	}
	if !found {
		return nil
	}
	return []ErrorCount{{Type: "corrected", Count: ce}, {Type: "uncorrected", Count: ue}}
}

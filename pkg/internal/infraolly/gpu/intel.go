package gpu

import (
	"path/filepath"
	"sync"
	"time"
)

// intelDevice reads Intel GPU telemetry from the i915 and xe driver sysfs and hwmon entries.
// See https://docs.kernel.org/gpu/i915.html and https://docs.kernel.org/gpu/xe/index.html
type intelDevice struct {
	info DeviceInfo
	card drmCard

	// i915 dGPUs and xe only expose cumulative energy, so power is derived
	// from the energy delta between samples
	mu         sync.Mutex
	lastEnergy float64
	lastTime   time.Time
	now        func() time.Time
}

func newIntelDevice(card drmCard) *intelDevice {
	return &intelDevice{
		info: DeviceInfo{Vendor: VendorIntel, ID: card.pciAddress, Name: "Intel GPU " + card.pciID, PCIAddress: card.pciAddress},
		card: card,
		now:  time.Now,
	}
}

func (d *intelDevice) Info() DeviceInfo { return d.info }

func (d *intelDevice) Close() {}

func (d *intelDevice) Sample() (*Sample, error) {
	s := &Sample{}
	if mhz, ok := d.graphicsClockMHz(); ok {
		s.Clocks = []Clock{{Domain: "graphics", Hertz: mhz * 1e6}}
	}
	hw := d.card.hwmonPath
	if hw == "" {
		return s, nil
	}
	s.Temperatures = hwmonTemperatures(hw)
	s.PowerLimitWatts = readMicro(filepath.Join(hw, "power1_max"))
	// xe exposes the card energy as energy1 and the package energy as energy2
	s.EnergyJoules = readMicro(filepath.Join(hw, "energy1_input"))
	s.PowerWatts = readMicro(filepath.Join(hw, "power1_average"), filepath.Join(hw, "power1_input"))
	if s.PowerWatts == nil && s.EnergyJoules != nil {
		s.PowerWatts = d.powerFromEnergy(*s.EnergyJoules)
	}
	if v, err := readInt(filepath.Join(hw, "fan1_input")); err == nil {
		s.FanSpeedRPM = ptr(float64(v))
	}
	return s, nil
}

func (d *intelDevice) graphicsClockMHz() (float64, bool) {
	for _, p := range []string{
		// i915 exposes the GT frequencies in the card directory
		filepath.Join(d.card.cardPath, "gt_act_freq_mhz"),
		filepath.Join(d.card.cardPath, "gt_cur_freq_mhz"),
		// xe exposes them per tile and GT
		filepath.Join(d.card.devPath, "tile0", "gt0", "freq0", "act_freq"),
		filepath.Join(d.card.devPath, "tile0", "gt0", "freq0", "cur_freq"),
	} {
		if v, err := readInt(p); err == nil {
			return float64(v), true
		}
	}
	return 0, false
}

func (d *intelDevice) powerFromEnergy(joules float64) *float64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	prevEnergy, prevTime := d.lastEnergy, d.lastTime
	d.lastEnergy, d.lastTime = joules, now
	elapsed := now.Sub(prevTime).Seconds()
	if prevTime.IsZero() || elapsed <= 0 || joules < prevEnergy {
		return nil
	}
	return ptr((joules - prevEnergy) / elapsed)
}

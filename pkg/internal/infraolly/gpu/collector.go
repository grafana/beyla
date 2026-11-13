package gpu

import (
	"log/slog"
	"strings"
	"sync"
	"time"
)

const (
	// rediscoveryInterval is the time between device discovery attempts while no
	// GPU has been found, as drivers might be loaded after Beyla starts.
	rediscoveryInterval = 30 * time.Second
	// defaultCacheTTL avoids reading the hardware twice when several exporters
	// (e.g. OTEL and Prometheus) collect at the same time.
	defaultCacheTTL = time.Second
)

// DeviceSample is the reading of a device at a given moment.
type DeviceSample struct {
	Info   DeviceInfo
	Sample *Sample
	// Processes is nil if the device does not support per-process attribution
	Processes []ProcessUsage
}

// CollectorConfig configures the GPU Collector.
type CollectorConfig struct {
	// SysRoot is the mount point of sysfs. Defaults to /sys
	SysRoot string
	// CacheTTL is the time a sample is reused by subsequent Collect invocations
	CacheTTL time.Duration
}

// Collector discovers the GPUs of the host and samples them on demand.
// It is safe for concurrent use.
type Collector struct {
	log      *slog.Logger
	sysRoot  string
	cacheTTL time.Duration
	now      func() time.Time
	// discover is overridable for testing
	discover func() []Device

	mu            sync.Mutex
	devices       []Device
	lastDiscovery time.Time
	lastSample    time.Time
	samples       []DeviceSample
	nvidiaWarned  bool
}

func NewCollector(cfg CollectorConfig) *Collector {
	c := &Collector{
		log:      glog(),
		sysRoot:  cfg.SysRoot,
		cacheTTL: cfg.CacheTTL,
		now:      time.Now,
	}
	if c.sysRoot == "" {
		c.sysRoot = "/sys"
	}
	if c.cacheTTL == 0 {
		c.cacheTTL = defaultCacheTTL
	}
	c.discover = c.discoverDevices
	return c
}

// Collect returns a sample of every discovered GPU.
func (c *Collector) Collect() []DeviceSample {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if !c.lastSample.IsZero() && now.Sub(c.lastSample) < c.cacheTTL {
		return c.samples
	}
	if len(c.devices) == 0 && (c.lastDiscovery.IsZero() || now.Sub(c.lastDiscovery) >= rediscoveryInterval) {
		c.lastDiscovery = now
		c.devices = c.discover()
	}
	c.lastSample = now
	c.samples = make([]DeviceSample, 0, len(c.devices))
	for _, dev := range c.devices {
		sample, err := dev.Sample()
		if err != nil {
			c.log.Debug("can't sample GPU", "id", dev.Info().ID, "error", err)
			continue
		}
		ds := DeviceSample{Info: dev.Info(), Sample: sample}
		if pr, ok := dev.(ProcessReporter); ok {
			procs, err := pr.Processes()
			if err != nil {
				c.log.Debug("can't get GPU processes", "id", dev.Info().ID, "error", err)
			}
			ds.Processes = procs
		}
		c.samples = append(c.samples, ds)
	}
	return c.samples
}

// Close releases the resources of the devices and vendor libraries.
func (c *Collector) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, dev := range c.devices {
		dev.Close()
	}
	c.devices = nil
	shutdownNVIDIA()
}

func (c *Collector) discoverDevices() []Device {
	var devices []Device
	cards, err := drmCards(c.sysRoot)
	if err != nil {
		c.log.Debug("can't list DRM cards", "error", err)
	}
	for _, card := range cards {
		var dev Device
		switch card.driver {
		case "amdgpu":
			dev = newAMDDevice(card)
		case "i915", "xe":
			dev = newIntelDevice(card)
		default:
			continue
		}
		c.log.Info("discovered GPU", "vendor", dev.Info().Vendor, "name", dev.Info().Name,
			"id", dev.Info().ID, "pci", card.pciAddress, "driver", card.driver)
		devices = append(devices, dev)
	}

	// NVIDIA GPUs are enumerated by NVML, as the proprietary driver barely exposes anything in sysfs
	if nvidiaPCI := pciDisplayDevices(c.sysRoot, pciVendorNVIDIA); len(nvidiaPCI) > 0 {
		nvDevices, err := discoverNVIDIA()
		if err != nil && !c.nvidiaWarned {
			c.nvidiaWarned = true
			c.log.Warn("NVIDIA GPUs found but their metrics can't be collected",
				"pci", nvidiaPCI, "error", err)
		}
		for _, dev := range nvDevices {
			c.log.Info("discovered GPU", "vendor", VendorNVIDIA, "name", dev.Info().Name,
				"id", dev.Info().ID, "pci", dev.Info().PCIAddress)
		}
		devices = append(devices, nvDevices...)
	}
	if len(devices) == 0 {
		c.log.Debug("no GPUs found. Retrying later", "interval", rediscoveryInterval)
	}
	return devices
}

// normalizeNVMLBusID converts the NVML bus ID (e.g. 00000000:01:00.0) to the
// sysfs PCI address format (e.g. 0000:01:00.0)
func normalizeNVMLBusID(busID string) string {
	domain, rest, ok := strings.Cut(strings.ToLower(busID), ":")
	if !ok {
		return strings.ToLower(busID)
	}
	if len(domain) > 4 {
		domain = domain[len(domain)-4:]
	}
	return domain + ":" + rest
}

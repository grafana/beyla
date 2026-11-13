package gpu

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSys builds a fake sysfs tree from a map of relative paths and contents,
// and the symlinks from /sys/class/drm/cardN to their device directory
type fakeSys struct {
	t    *testing.T
	root string
}

func newFakeSys(t *testing.T) *fakeSys {
	return &fakeSys{t: t, root: t.TempDir()}
}

func (f *fakeSys) write(files map[string]string) {
	for path, content := range files {
		full := filepath.Join(f.root, path)
		require.NoError(f.t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(f.t, os.WriteFile(full, []byte(content+"\n"), 0o644))
	}
}

// card creates a DRM card with its PCI device, and returns the device directory relative to the root
func (f *fakeSys) card(card, pciAddr, pciID, vendor, driver string) string {
	dev := filepath.Join("devices", "pci0000:00", pciAddr)
	f.write(map[string]string{
		filepath.Join(dev, "uevent"): "DRIVER=" + driver + "\nPCI_ID=" + pciID + "\nPCI_SLOT_NAME=" + pciAddr,
		filepath.Join(dev, "class"):  "0x030000",
		filepath.Join(dev, "vendor"): vendor,
	})
	cardDir := filepath.Join(f.root, "class", "drm", card)
	require.NoError(f.t, os.MkdirAll(cardDir, 0o755))
	require.NoError(f.t, os.Symlink(filepath.Join(f.root, dev), filepath.Join(cardDir, "device")))
	pciLink := filepath.Join(f.root, "bus", "pci", "devices", pciAddr)
	require.NoError(f.t, os.MkdirAll(filepath.Dir(pciLink), 0o755))
	require.NoError(f.t, os.Symlink(filepath.Join(f.root, dev), pciLink))
	return dev
}

func TestDiscover(t *testing.T) {
	sys := newFakeSys(t)
	amd := sys.card("card0", "0000:03:00.0", "1002:744C", pciVendorAMD, "amdgpu")
	sys.write(map[string]string{
		filepath.Join(amd, "product_name"): "Radeon RX 7900 XTX",
		filepath.Join(amd, "unique_id"):    "a1b2c3d4",
	})
	sys.card("card1", "0000:00:02.0", "8086:A7A0", pciVendorIntel, "i915")
	sys.card("card2", "0000:05:00.0", "1234:0001", "0x1234", "simpledrm")
	// connectors must be ignored
	require.NoError(t, os.MkdirAll(filepath.Join(sys.root, "class", "drm", "card0-DP-1"), 0o755))

	c := NewCollector(CollectorConfig{SysRoot: sys.root})
	devices := c.discoverDevices()
	require.Len(t, devices, 2)
	infos := []DeviceInfo{devices[0].Info(), devices[1].Info()}
	assert.ElementsMatch(t, []DeviceInfo{
		{Vendor: VendorAMD, ID: "a1b2c3d4", Name: "Radeon RX 7900 XTX", PCIAddress: "0000:03:00.0"},
		{Vendor: VendorIntel, ID: "0000:00:02.0", Name: "Intel GPU 8086:A7A0", PCIAddress: "0000:00:02.0"},
	}, infos)
}

func TestDiscover_NVIDIAWithoutNVML(t *testing.T) {
	sys := newFakeSys(t)
	sys.card("card0", "0000:01:00.0", "10DE:2330", pciVendorNVIDIA, "nvidia")
	c := NewCollector(CollectorConfig{SysRoot: sys.root})
	// without the beyla_nvml build tag (or without the NVML library) no device can be discovered
	assert.Empty(t, c.discoverDevices())
	assert.True(t, c.nvidiaWarned)
}

func TestAMDSample(t *testing.T) {
	sys := newFakeSys(t)
	dev := sys.card("card0", "0000:03:00.0", "1002:744C", pciVendorAMD, "amdgpu")
	hw := filepath.Join(dev, "hwmon", "hwmon4")
	sys.write(map[string]string{
		filepath.Join(dev, "gpu_busy_percent"):     "42",
		filepath.Join(dev, "mem_busy_percent"):     "7",
		filepath.Join(dev, "mem_info_vram_total"):  "25753026560",
		filepath.Join(dev, "mem_info_vram_used"):   "1073741824",
		filepath.Join(dev, "ras", "umc_err_count"): "ue: 1\nce: 3",
		filepath.Join(dev, "ras", "gfx_err_count"): "ue: 0\nce: 2",
		filepath.Join(dev, "ras", "features"):      "feature mask: 0x3",
		filepath.Join(hw, "temp1_input"):           "45000",
		filepath.Join(hw, "temp1_label"):           "edge",
		filepath.Join(hw, "temp2_input"):           "52000",
		filepath.Join(hw, "temp2_label"):           "junction",
		filepath.Join(hw, "temp3_input"):           "60000",
		filepath.Join(hw, "temp3_label"):           "mem",
		filepath.Join(hw, "power1_input"):          "95000000",
		filepath.Join(hw, "power1_cap"):            "300000000",
		filepath.Join(hw, "energy1_input"):         "1500000000",
		filepath.Join(hw, "freq1_input"):           "2100000000",
		filepath.Join(hw, "freq1_label"):           "sclk",
		filepath.Join(hw, "freq2_input"):           "1250000000",
		filepath.Join(hw, "freq2_label"):           "mclk",
		filepath.Join(hw, "fan1_input"):            "1200",
	})
	c := NewCollector(CollectorConfig{SysRoot: sys.root})
	devices := c.discoverDevices()
	require.Len(t, devices, 1)

	s, err := devices[0].Sample()
	require.NoError(t, err)
	assert.Equal(t, &Sample{
		Utilization:                 ptr(0.42),
		MemoryControllerUtilization: ptr(0.07),
		MemoryLimitBytes:            ptr(int64(25753026560)),
		MemoryUsedBytes:             ptr(int64(1073741824)),
		PowerWatts:                  ptr(95.0),
		PowerLimitWatts:             ptr(300.0),
		EnergyJoules:                ptr(1500.0),
		FanSpeedRPM:                 ptr(1200.0),
		Temperatures: []Temperature{
			{Location: "edge", Celsius: 45}, {Location: "junction", Celsius: 52}, {Location: "mem", Celsius: 60},
		},
		Clocks: []Clock{{Domain: "graphics", Hertz: 2.1e9}, {Domain: "memory", Hertz: 1.25e9}},
		Errors: []ErrorCount{{Type: "corrected", Count: 5}, {Type: "uncorrected", Count: 1}},
	}, s)
}

func TestAMDSample_PrefersAveragePower(t *testing.T) {
	sys := newFakeSys(t)
	dev := sys.card("card0", "0000:03:00.0", "1002:744C", pciVendorAMD, "amdgpu")
	hw := filepath.Join(dev, "hwmon", "hwmon4")
	sys.write(map[string]string{
		filepath.Join(hw, "power1_average"): "80000000",
		filepath.Join(hw, "power1_input"):   "95000000",
	})
	s, err := newAMDDevice(drmCard{devPath: filepath.Join(sys.root, dev), hwmonPath: filepath.Join(sys.root, hw)}).Sample()
	require.NoError(t, err)
	assert.Equal(t, ptr(80.0), s.PowerWatts)
	assert.Nil(t, s.Utilization)
	assert.Nil(t, s.Errors)
}

func TestIntelSample(t *testing.T) {
	sys := newFakeSys(t)
	dev := sys.card("card0", "0000:03:00.0", "8086:56A0", pciVendorIntel, "i915")
	hw := filepath.Join(dev, "hwmon", "hwmon2")
	sys.write(map[string]string{
		filepath.Join("class", "drm", "card0", "gt_act_freq_mhz"): "1800",
		filepath.Join(hw, "power1_max"):                           "190000000",
		filepath.Join(hw, "energy1_input"):                        "1000000000",
		filepath.Join(hw, "temp1_input"):                          "40000",
	})
	c := NewCollector(CollectorConfig{SysRoot: sys.root})
	devices := c.discoverDevices()
	require.Len(t, devices, 1)
	intel := devices[0].(*intelDevice)
	now := time.Unix(1000, 0)
	intel.now = func() time.Time { return now }

	s, err := intel.Sample()
	require.NoError(t, err)
	assert.Equal(t, &Sample{
		PowerLimitWatts: ptr(190.0),
		EnergyJoules:    ptr(1000.0),
		Temperatures:    []Temperature{{Location: "temp1", Celsius: 40}},
		Clocks:          []Clock{{Domain: "graphics", Hertz: 1.8e9}},
	}, s)

	// power is derived from the energy consumed since the previous sample
	now = now.Add(2 * time.Second)
	sys.write(map[string]string{filepath.Join(hw, "energy1_input"): "1100000000"})
	s, err = intel.Sample()
	require.NoError(t, err)
	assert.Equal(t, ptr(50.0), s.PowerWatts)
}

type fakeDevice struct {
	info    DeviceInfo
	samples int
	procs   []ProcessUsage
}

func (f *fakeDevice) Info() DeviceInfo { return f.info }
func (f *fakeDevice) Close()           {}
func (f *fakeDevice) Sample() (*Sample, error) {
	f.samples++
	return &Sample{Utilization: ptr(float64(f.samples) / 10)}, nil
}
func (f *fakeDevice) Processes() ([]ProcessUsage, error) { return f.procs, nil }

func TestCollector_CacheAndRediscovery(t *testing.T) {
	now := time.Unix(1000, 0)
	discoveries := 0
	var found []Device
	c := NewCollector(CollectorConfig{CacheTTL: time.Second})
	c.now = func() time.Time { return now }
	c.discover = func() []Device { discoveries++; return found }

	assert.Empty(t, c.Collect())
	assert.Equal(t, 1, discoveries)

	// no rediscovery until the rediscovery interval passes
	now = now.Add(10 * time.Second)
	dev := &fakeDevice{info: DeviceInfo{ID: "gpu-0"}, procs: []ProcessUsage{{PID: 123}}}
	found = []Device{dev}
	assert.Empty(t, c.Collect())
	assert.Equal(t, 1, discoveries)

	now = now.Add(rediscoveryInterval)
	samples := c.Collect()
	assert.Equal(t, 2, discoveries)
	require.Len(t, samples, 1)
	assert.Equal(t, "gpu-0", samples[0].Info.ID)
	assert.Equal(t, ptr(0.1), samples[0].Sample.Utilization)
	assert.Equal(t, []ProcessUsage{{PID: 123}}, samples[0].Processes)

	// concurrent collections within the cache TTL reuse the sample
	now = now.Add(500 * time.Millisecond)
	assert.Equal(t, ptr(0.1), c.Collect()[0].Sample.Utilization)
	now = now.Add(time.Second)
	assert.Equal(t, ptr(0.2), c.Collect()[0].Sample.Utilization)
	// devices were found, so there is no further discovery
	now = now.Add(2 * rediscoveryInterval)
	c.Collect()
	assert.Equal(t, 2, discoveries)
}

func TestNormalizeNVMLBusID(t *testing.T) {
	assert.Equal(t, "0000:01:00.0", normalizeNVMLBusID("00000000:01:00.0"))
	assert.Equal(t, "0001:af:00.0", normalizeNVMLBusID("00000001:AF:00.0"))
	assert.Equal(t, "0000:01:00.0", normalizeNVMLBusID("0000:01:00.0"))
	assert.Equal(t, "garbage", normalizeNVMLBusID("garbage"))
}

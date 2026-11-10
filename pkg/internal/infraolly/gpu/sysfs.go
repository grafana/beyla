package gpu

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	pciVendorNVIDIA = "0x10de"
	pciVendorAMD    = "0x1002"
	pciVendorIntel  = "0x8086"
)

// drmCard is a GPU exposed through the kernel DRM subsystem (/sys/class/drm/cardN).
type drmCard struct {
	// cardPath is the DRM card directory, e.g. /sys/class/drm/card0
	cardPath string
	// devPath is the PCI device directory, e.g. /sys/class/drm/card0/device
	devPath    string
	pciAddress string
	pciID      string
	driver     string
	// hwmonPath is the hwmon directory of the device, or empty if the driver exposes none
	hwmonPath string
}

// drmCards lists the DRM cards of the host, skipping connector entries such as card0-DP-1.
func drmCards(sysRoot string) ([]drmCard, error) {
	drmClass := filepath.Join(sysRoot, "class", "drm")
	entries, err := os.ReadDir(drmClass)
	if err != nil {
		return nil, fmt.Errorf("reading DRM class: %w", err)
	}
	var cards []drmCard
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "card") || strings.Contains(name, "-") {
			continue
		}
		cardPath := filepath.Join(drmClass, name)
		devPath := filepath.Join(cardPath, "device")
		uevent := readString(filepath.Join(devPath, "uevent"))
		card := drmCard{
			cardPath:   cardPath,
			devPath:    devPath,
			pciAddress: ueventValue(uevent, "PCI_SLOT_NAME"),
			pciID:      ueventValue(uevent, "PCI_ID"),
			driver:     ueventValue(uevent, "DRIVER"),
			hwmonPath:  firstHwmon(devPath),
		}
		if card.pciAddress == "" || card.driver == "" {
			continue
		}
		cards = append(cards, card)
	}
	return cards, nil
}

// pciDisplayDevices returns the PCI addresses of the display controllers of the given vendor.
func pciDisplayDevices(sysRoot, vendorID string) []string {
	pciDevices := filepath.Join(sysRoot, "bus", "pci", "devices")
	entries, err := os.ReadDir(pciDevices)
	if err != nil {
		return nil
	}
	var addresses []string
	for _, entry := range entries {
		devPath := filepath.Join(pciDevices, entry.Name())
		// PCI base class 0x03 groups VGA, 3D and other display controllers
		if !strings.HasPrefix(readString(filepath.Join(devPath, "class")), "0x03") {
			continue
		}
		if strings.EqualFold(readString(filepath.Join(devPath, "vendor")), vendorID) {
			addresses = append(addresses, entry.Name())
		}
	}
	return addresses
}

func firstHwmon(devPath string) string {
	entries, err := os.ReadDir(filepath.Join(devPath, "hwmon"))
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "hwmon") {
			return filepath.Join(devPath, "hwmon", e.Name())
		}
	}
	return ""
}

// hwmonTemperatures reads all the tempN_input sensors, using tempN_label as location
// when available (e.g. amdgpu exposes "edge", "junction" and "mem").
func hwmonTemperatures(hwmonPath string) []Temperature {
	inputs, _ := filepath.Glob(filepath.Join(hwmonPath, "temp*_input"))
	var temps []Temperature
	for _, input := range inputs {
		milliC, err := readInt(input)
		if err != nil {
			continue
		}
		location := readString(strings.TrimSuffix(input, "_input") + "_label")
		if location == "" {
			location = strings.TrimSuffix(filepath.Base(input), "_input")
		}
		temps = append(temps, Temperature{Location: location, Celsius: float64(milliC) / 1000})
	}
	return temps
}

// readMicro reads the first available sysfs entry holding a value in micro-units
// (microwatts, microjoules) and returns it in base units.
func readMicro(paths ...string) *float64 {
	for _, p := range paths {
		if v, err := readInt(p); err == nil {
			return ptr(float64(v) / 1e6)
		}
	}
	return nil
}

func readRatioPercent(path string) *float64 {
	if v, err := readInt(path); err == nil {
		return ptr(float64(v) / 100)
	}
	return nil
}

func readString(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readInt(path string) (int64, error) {
	return strconv.ParseInt(readString(path), 10, 64)
}

func ueventValue(uevent, key string) string {
	for _, line := range strings.Split(uevent, "\n") {
		if v, ok := strings.CutPrefix(line, key+"="); ok {
			return v
		}
	}
	return ""
}

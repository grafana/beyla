// Package gpu reads hardware telemetry from the GPUs installed in the host.
package gpu

import "log/slog"

func glog() *slog.Logger {
	return slog.With("component", "gpu.Collector")
}

// Vendor identifies the GPU manufacturer. Values match the hw.vendor attribute.
type Vendor string

const (
	VendorNVIDIA Vendor = "nvidia"
	VendorAMD    Vendor = "amd"
	VendorIntel  Vendor = "intel"
)

// DeviceInfo holds static identification data for a GPU.
type DeviceInfo struct {
	Vendor Vendor
	// ID is a stable, unique identifier of the device (hw.id): the NVML UUID for NVIDIA,
	// the unique_id sysfs entry for AMD, or the PCI address when nothing better is available.
	ID         string
	Name       string
	PCIAddress string
}

// Temperature reading of a given sensor (hw.sensor_location), in degrees Celsius.
type Temperature struct {
	Location string
	Celsius  float64
}

// Clock frequency of a given clock domain (hw.gpu.clock_domain), in Hertz.
type Clock struct {
	Domain string
	Hertz  float64
}

// ErrorCount is a cumulative counter of hardware errors of a given type (error.type).
type ErrorCount struct {
	Type  string
	Count int64
}

// Sample is a point-in-time reading of a GPU.
// Values are already normalised to the units of the OpenTelemetry hardware semantic
// conventions (ratios in the 0..1 range, bytes, watts, joules, hertz).
// Nil pointers and empty slices mean that the value is not available for the device.
type Sample struct {
	Utilization        *float64
	EncoderUtilization *float64
	DecoderUtilization *float64
	// MemoryControllerUtilization is the fraction of time the memory controller was busy.
	MemoryControllerUtilization *float64

	MemoryLimitBytes *int64
	MemoryUsedBytes  *int64

	PowerWatts      *float64
	PowerLimitWatts *float64
	EnergyJoules    *float64

	FanSpeedRPM   *float64
	FanSpeedRatio *float64

	Temperatures []Temperature
	Clocks       []Clock
	Errors       []ErrorCount
}

// ProcessUsage is the GPU usage of a single process on a device.
type ProcessUsage struct {
	PID         uint32
	MemoryBytes *int64
	Utilization *float64
}

// Device is implemented by each vendor backend.
type Device interface {
	Info() DeviceInfo
	Sample() (*Sample, error)
	Close()
}

// ProcessReporter is optionally implemented by the backends able to attribute GPU usage
// to processes.
type ProcessReporter interface {
	Processes() ([]ProcessUsage, error)
}

func ptr[T any](v T) *T { return &v }

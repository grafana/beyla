// Package gpumetrics exports the GPU hardware metrics, following the OpenTelemetry
// semantic conventions for hardware: https://opentelemetry.io/docs/specs/semconv/hardware/gpu/
package gpumetrics

import (
	"strconv"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"

	"github.com/grafana/beyla/v3/pkg/internal/infraolly/gpu"
)

const (
	hwID           = attr.Name("hw.id")
	hwName         = attr.Name("hw.name")
	hwVendor       = attr.Name("hw.vendor")
	hwType         = attr.Name("hw.type")
	hwGPUTask      = attr.Name("hw.gpu.task")
	hwSensorLoc    = attr.Name("hw.sensor_location")
	hwClockDomain  = attr.Name("hw.gpu.clock_domain")
	errorType      = attr.Name("error.type")
	processPID     = attr.Name("process.pid")
	serviceName    = attr.Name("service.name")
	serviceNS      = attr.Name("service.namespace")
	serviceInst    = attr.Name("service.instance.id")
	hostID         = attr.Name("host.id")
	hostName       = attr.Name("host.name")
	hwTypeGPUValue = "gpu"
)

type instrumentKind int

const (
	kindGauge instrumentKind = iota
	kindUpDownCounter
	kindCounter
)

type metricDef struct {
	otel   string
	prom   string
	help   string
	unit   string
	kind   instrumentKind
	labels []attr.Name
}

var (
	deviceLabels  = []attr.Name{hwID, hwName, hwVendor}
	processLabels = []attr.Name{hwID, processPID, serviceName, serviceNS, serviceInst}
)

func withLabels(base []attr.Name, extra ...attr.Name) []attr.Name {
	return append(append([]attr.Name{}, base...), extra...)
}

var (
	gpuUtilization = &metricDef{
		otel: "hw.gpu.utilization", prom: "hw_gpu_utilization_ratio", unit: "1", kind: kindGauge,
		help:   "Fraction of time the GPU was busy, by task",
		labels: withLabels(deviceLabels, hwGPUTask),
	}
	gpuMemoryUtilization = &metricDef{
		otel: "hw.gpu.memory.utilization", prom: "hw_gpu_memory_utilization_ratio", unit: "1", kind: kindGauge,
		help:   "Fraction of GPU memory used",
		labels: deviceLabels,
	}
	gpuMemoryControllerUtilization = &metricDef{
		otel: "hw.gpu.memory.controller.utilization", prom: "hw_gpu_memory_controller_utilization_ratio", unit: "1", kind: kindGauge,
		help:   "Fraction of time the GPU memory controller was busy",
		labels: deviceLabels,
	}
	gpuMemoryLimit = &metricDef{
		otel: "hw.gpu.memory.limit", prom: "hw_gpu_memory_limit_bytes", unit: "By", kind: kindUpDownCounter,
		help:   "Total GPU memory",
		labels: deviceLabels,
	}
	gpuMemoryUsage = &metricDef{
		otel: "hw.gpu.memory.usage", prom: "hw_gpu_memory_usage_bytes", unit: "By", kind: kindUpDownCounter,
		help:   "Used GPU memory",
		labels: deviceLabels,
	}
	gpuSpeed = &metricDef{
		otel: "hw.gpu.speed", prom: "hw_gpu_speed_hertz", unit: "Hz", kind: kindGauge,
		help:   "GPU clock frequency, by clock domain",
		labels: withLabels(deviceLabels, hwClockDomain),
	}
	hwTemperature = &metricDef{
		otel: "hw.temperature", prom: "hw_temperature_celsius", unit: "Cel", kind: kindGauge,
		help:   "GPU temperature, by sensor location",
		labels: withLabels(deviceLabels, hwSensorLoc),
	}
	hwPower = &metricDef{
		otel: "hw.power", prom: "hw_power_watts", unit: "W", kind: kindGauge,
		help:   "GPU power draw",
		labels: deviceLabels,
	}
	hwPowerLimit = &metricDef{
		otel: "hw.power.limit", prom: "hw_power_limit_watts", unit: "W", kind: kindGauge,
		help:   "GPU power limit",
		labels: deviceLabels,
	}
	hwEnergy = &metricDef{
		otel: "hw.energy", prom: "hw_energy_joules_total", unit: "J", kind: kindCounter,
		help:   "Cumulative GPU energy consumption",
		labels: deviceLabels,
	}
	hwFanSpeed = &metricDef{
		otel: "hw.fan.speed", prom: "hw_fan_speed_rpm", unit: "rpm", kind: kindGauge,
		help:   "GPU fan speed",
		labels: deviceLabels,
	}
	hwFanSpeedRatio = &metricDef{
		otel: "hw.fan.speed_ratio", prom: "hw_fan_speed_ratio", unit: "1", kind: kindGauge,
		help:   "GPU fan speed as a fraction of its maximum speed",
		labels: deviceLabels,
	}
	hwErrors = &metricDef{
		otel: "hw.errors", prom: "hw_errors_total", unit: "{error}", kind: kindCounter,
		help:   "Cumulative GPU hardware errors, by error type",
		labels: withLabels(deviceLabels, errorType, hwType),
	}
	processGPUMemoryUsage = &metricDef{
		otel: "process.gpu.memory.usage", prom: "process_gpu_memory_usage_bytes", unit: "By", kind: kindUpDownCounter,
		help:   "GPU memory used by an instrumented process",
		labels: processLabels,
	}
	processGPUUtilization = &metricDef{
		otel: "process.gpu.utilization", prom: "process_gpu_utilization_ratio", unit: "1", kind: kindGauge,
		help:   "Fraction of time an instrumented process used the GPU streaming multiprocessors",
		labels: processLabels,
	}
)

var allMetrics = []*metricDef{
	gpuUtilization, gpuMemoryUtilization, gpuMemoryControllerUtilization, gpuMemoryLimit, gpuMemoryUsage,
	gpuSpeed, hwTemperature, hwPower, hwPowerLimit, hwEnergy, hwFanSpeed, hwFanSpeedRatio, hwErrors,
	processGPUMemoryUsage, processGPUUtilization,
}

// Source provides the GPU samples. It is implemented by *gpu.Collector.
type Source interface {
	Collect() []gpu.DeviceSample
}

// emitFunc receives a metric value along with the values of all the labels in def.labels, in the same order
type emitFunc func(def *metricDef, value float64, labelValues ...string)

// observe converts the GPU samples into metric values. Per-process metrics are
// only emitted for the processes tracked by Beyla.
func observe(samples []gpu.DeviceSample, procs *processes, emit emitFunc) {
	for i := range samples {
		observeDevice(&samples[i], emit)
		if procs != nil {
			observeProcesses(&samples[i], procs, emit)
		}
	}
}

func observeDevice(ds *gpu.DeviceSample, emit emitFunc) {
	s := ds.Sample
	dev := []string{ds.Info.ID, ds.Info.Name, string(ds.Info.Vendor)}
	with := func(extra ...string) []string { return append(append([]string{}, dev...), extra...) }
	gauge := func(def *metricDef, v *float64) {
		if v != nil {
			emit(def, *v, dev...)
		}
	}

	if s.Utilization != nil {
		emit(gpuUtilization, *s.Utilization, with("general")...)
	}
	if s.EncoderUtilization != nil {
		emit(gpuUtilization, *s.EncoderUtilization, with("encoder")...)
	}
	if s.DecoderUtilization != nil {
		emit(gpuUtilization, *s.DecoderUtilization, with("decoder")...)
	}
	gauge(gpuMemoryControllerUtilization, s.MemoryControllerUtilization)
	if s.MemoryLimitBytes != nil {
		emit(gpuMemoryLimit, float64(*s.MemoryLimitBytes), dev...)
	}
	if s.MemoryUsedBytes != nil {
		emit(gpuMemoryUsage, float64(*s.MemoryUsedBytes), dev...)
		if s.MemoryLimitBytes != nil && *s.MemoryLimitBytes > 0 {
			emit(gpuMemoryUtilization, float64(*s.MemoryUsedBytes)/float64(*s.MemoryLimitBytes), dev...)
		}
	}
	for _, c := range s.Clocks {
		emit(gpuSpeed, c.Hertz, with(c.Domain)...)
	}
	for _, t := range s.Temperatures {
		emit(hwTemperature, t.Celsius, with(t.Location)...)
	}
	gauge(hwPower, s.PowerWatts)
	gauge(hwPowerLimit, s.PowerLimitWatts)
	gauge(hwEnergy, s.EnergyJoules)
	gauge(hwFanSpeed, s.FanSpeedRPM)
	gauge(hwFanSpeedRatio, s.FanSpeedRatio)
	for _, e := range s.Errors {
		emit(hwErrors, float64(e.Count), with(e.Type, hwTypeGPUValue)...)
	}
}

func observeProcesses(ds *gpu.DeviceSample, procs *processes, emit emitFunc) {
	for _, p := range ds.Processes {
		uid, ok := procs.get(p.PID)
		if !ok {
			continue
		}
		lbls := []string{ds.Info.ID, strconv.FormatUint(uint64(p.PID), 10), uid.Name, uid.Namespace, uid.Instance}
		if p.MemoryBytes != nil {
			emit(processGPUMemoryUsage, float64(*p.MemoryBytes), lbls...)
		}
		if p.Utilization != nil {
			emit(processGPUUtilization, *p.Utilization, lbls...)
		}
	}
}

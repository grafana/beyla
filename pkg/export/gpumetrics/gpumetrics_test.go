package gpumetrics

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/pipe/msg"

	"github.com/grafana/beyla/v3/pkg/export/otel/bexport"
	"github.com/grafana/beyla/v3/pkg/internal/infraolly/gpu"
)

func ptr[T any](v T) *T { return &v }

func testSamples() []gpu.DeviceSample {
	return []gpu.DeviceSample{{
		Info: gpu.DeviceInfo{Vendor: gpu.VendorNVIDIA, ID: "GPU-1234", Name: "NVIDIA H100"},
		Sample: &gpu.Sample{
			Utilization:        ptr(0.5),
			EncoderUtilization: ptr(0.1),
			MemoryLimitBytes:   ptr(int64(1000)),
			MemoryUsedBytes:    ptr(int64(250)),
			PowerWatts:         ptr(300.0),
			EnergyJoules:       ptr(12345.0),
			Temperatures:       []gpu.Temperature{{Location: "die", Celsius: 60}},
			Clocks:             []gpu.Clock{{Domain: "sm", Hertz: 1.98e9}},
			Errors:             []gpu.ErrorCount{{Type: "uncorrected", Count: 2}},
		},
		Processes: []gpu.ProcessUsage{
			{PID: 100, MemoryBytes: ptr(int64(200)), Utilization: ptr(0.4)},
			// not instrumented by Beyla
			{PID: 200, MemoryBytes: ptr(int64(50))},
		},
	}}
}

func gpuProcessEvent(pid app.PID, name string, features export.Features) exec.ProcessEvent {
	return exec.ProcessEvent{Type: exec.ProcessEventCreated, File: exec.New(exec.Init{
		Pid:     pid,
		Service: svc.Attrs{UID: svc.UID{Name: name, Namespace: "ns", Instance: name + "-1"}, Features: features},
	})}
}

type point struct {
	value  float64
	labels string
}

func TestObserve(t *testing.T) {
	procs := newProcesses()
	procs.process(gpuProcessEvent(100, "llm", bexport.FeatureGPU))
	procs.process(gpuProcessEvent(200, "other", bexport.FeatureProcess))

	got := map[string][]point{}
	observe(testSamples(), procs, func(def *metricDef, value float64, labelValues ...string) {
		require.Len(t, labelValues, len(def.labels), def.otel)
		got[def.otel] = append(got[def.otel], point{value: value, labels: strings.Join(labelValues, ",")})
	})

	dev := "GPU-1234,NVIDIA H100,nvidia"
	assert.Equal(t, map[string][]point{
		"hw.gpu.utilization":        {{0.5, dev + ",general"}, {0.1, dev + ",encoder"}},
		"hw.gpu.memory.limit":       {{1000, dev}},
		"hw.gpu.memory.usage":       {{250, dev}},
		"hw.gpu.memory.utilization": {{0.25, dev}},
		"hw.gpu.speed":              {{1.98e9, dev + ",sm"}},
		"hw.temperature":            {{60, dev + ",die"}},
		"hw.power":                  {{300, dev}},
		"hw.energy":                 {{12345, dev}},
		"hw.errors":                 {{2, dev + ",uncorrected,gpu"}},
		"process.gpu.memory.usage":  {{200, "GPU-1234,100,llm,ns,llm-1"}},
		"process.gpu.utilization":   {{0.4, "GPU-1234,100,llm,ns,llm-1"}},
	}, got)
}

func TestProcesses_Lifecycle(t *testing.T) {
	procs := newProcesses()
	started := gpuProcessEvent(100, "llm", bexport.FeatureGPU)
	procs.process(started)
	_, ok := procs.get(100)
	require.True(t, ok)

	// a termination event from a previous process with the same PID is ignored
	stale := exec.ProcessEvent{Type: exec.ProcessEventTerminated, File: exec.New(exec.Init{Pid: 100, StartTime: 1})}
	procs.process(stale)
	_, ok = procs.get(100)
	require.True(t, ok)

	procs.process(exec.ProcessEvent{Type: exec.ProcessEventTerminated, File: started.File})
	_, ok = procs.get(100)
	require.False(t, ok)
}

func TestPromCollector(t *testing.T) {
	procs := newProcesses()
	procs.process(gpuProcessEvent(100, "llm", bexport.FeatureGPU))
	pc := newPromCollector(&PromConfig{HostID: "host-1", HostName: "node-a"}, fakeSource(testSamples()), procs)

	registry := prometheus.NewRegistry()
	require.NoError(t, registry.Register(pc))
	require.NoError(t, testutil.GatherAndCompare(registry, strings.NewReader(`
# HELP hw_energy_joules_total Cumulative GPU energy consumption
# TYPE hw_energy_joules_total counter
hw_energy_joules_total{host_id="host-1",host_name="node-a",hw_id="GPU-1234",hw_name="NVIDIA H100",hw_vendor="nvidia"} 12345
# HELP hw_gpu_utilization_ratio Fraction of time the GPU was busy, by task
# TYPE hw_gpu_utilization_ratio gauge
hw_gpu_utilization_ratio{host_id="host-1",host_name="node-a",hw_gpu_task="encoder",hw_id="GPU-1234",hw_name="NVIDIA H100",hw_vendor="nvidia"} 0.1
hw_gpu_utilization_ratio{host_id="host-1",host_name="node-a",hw_gpu_task="general",hw_id="GPU-1234",hw_name="NVIDIA H100",hw_vendor="nvidia"} 0.5
# HELP process_gpu_memory_usage_bytes GPU memory used by an instrumented process
# TYPE process_gpu_memory_usage_bytes gauge
process_gpu_memory_usage_bytes{host_id="host-1",host_name="node-a",hw_id="GPU-1234",process_pid="100",service_instance_id="llm-1",service_name="llm",service_namespace="ns"} 200
`), "hw_energy_joules_total", "hw_gpu_utilization_ratio", "process_gpu_memory_usage_bytes"))
}

func TestOTELInstruments(t *testing.T) {
	collector := fakeSource(testSamples())
	procs := newProcesses()
	procs.process(gpuProcessEvent(100, "llm", bexport.FeatureGPU))
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	require.NoError(t, registerInstruments(provider, collector, procs))

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(t.Context(), &rm))
	require.Len(t, rm.ScopeMetrics, 1)
	byName := map[string]metricdata.Metrics{}
	for _, m := range rm.ScopeMetrics[0].Metrics {
		byName[m.Name] = m
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	assert.Equal(t, []string{
		"hw.energy", "hw.errors", "hw.gpu.memory.limit", "hw.gpu.memory.usage", "hw.gpu.memory.utilization",
		"hw.gpu.speed", "hw.gpu.utilization", "hw.power", "hw.temperature",
		"process.gpu.memory.usage", "process.gpu.utilization",
	}, names)

	energy := byName["hw.energy"]
	assert.Equal(t, "J", energy.Unit)
	sum, ok := energy.Data.(metricdata.Sum[float64])
	require.True(t, ok)
	assert.True(t, sum.IsMonotonic)
	require.Len(t, sum.DataPoints, 1)
	assert.Equal(t, 12345.0, sum.DataPoints[0].Value)
	id, _ := sum.DataPoints[0].Attributes.Value("hw.id")
	assert.Equal(t, "GPU-1234", id.AsString())

	memUsage, ok := byName["hw.gpu.memory.usage"].Data.(metricdata.Sum[float64])
	require.True(t, ok)
	assert.False(t, memUsage.IsMonotonic)

	util, ok := byName["process.gpu.utilization"].Data.(metricdata.Gauge[float64])
	require.True(t, ok)
	require.Len(t, util.DataPoints, 1)
	svcName, _ := util.DataPoints[0].Attributes.Value("service.name")
	assert.Equal(t, "llm", svcName.AsString())
}

func TestPromExport_TracksProcessEvents(t *testing.T) {
	events := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(10))
	registry := prometheus.NewRegistry()
	var registered *promCollector
	run, err := PromExport(PromConfig{Enabled: true, Register: func(c prometheus.Collector) error {
		registered = c.(*promCollector)
		return registry.Register(c)
	}}, fakeSource(nil), events)(t.Context())
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go run(ctx)

	events.Send(gpuProcessEvent(100, "llm", bexport.FeatureGPU))
	require.Eventually(t, func() bool {
		_, ok := registered.procs.get(100)
		return ok
	}, time.Second, time.Millisecond)
}

type fakeSource []gpu.DeviceSample

func (f fakeSource) Collect() []gpu.DeviceSample { return f }

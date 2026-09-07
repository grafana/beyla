// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes // import "go.opentelemetry.io/obi/pkg/export/attributes"

import (
	"fmt"
	"strings"

	"github.com/prometheus/otlptranslator"
)

// Section of the attributes.select configuration. They are metric names
// using the dot.notation and suppressing any .total .sum or .count suffix.
// They are used as a standardized key in the attributes.select map, whichever
// metric format or name the user provides.
type Section string

// Instrument is the kind of instrument a metric is recorded with. It selects the
// type suffix a Prometheus consumer appends to the metric name.
type Instrument uint8

const (
	InstrumentUnknown Instrument = iota
	InstrumentCounter
	InstrumentUpDownCounter
	InstrumentGauge
	InstrumentHistogram
)

func (i Instrument) otlp() otlptranslator.MetricType {
	switch i {
	case InstrumentCounter:
		return otlptranslator.MetricTypeMonotonicCounter
	case InstrumentUpDownCounter:
		return otlptranslator.MetricTypeNonMonotonicCounter
	case InstrumentGauge:
		return otlptranslator.MetricTypeGauge
	case InstrumentHistogram:
		return otlptranslator.MetricTypeHistogram
	default:
		return otlptranslator.MetricTypeUnknown
	}
}

// Name of a metric. OTEL, Unit and Type are the definition; Prom is derived from
// them so that OBI's Prometheus exporter and any Prometheus consumer of OBI's OTLP
// output name the same metric identically.
type Name struct {
	// Section name in the attributes.select configuration option. It is
	// a normalized form accorting to the normalizeMetric function below.
	// It makes sure that it does not have metric nor aggregation suffix.
	Section Section
	// OTEL name of a metric for the OTEL exporter
	OTEL string
	// Unit of the metric, in UCUM notation, as declared to the OTEL instrument
	Unit string
	// Type of instrument the metric is recorded with
	Type Instrument
	// Prom name of a metric for the Prometheus exporter. Derived, never set by hand.
	Prom string
}

// metric derives the Prometheus name of a metric from its OTLP definition, applying the
// same translation a collector re-exporting OBI's OTLP metrics in Prometheus format does.
func metric(n Name) Name {
	namer := otlptranslator.MetricNamer{WithMetricSuffixes: true}

	prom, err := namer.Build(otlptranslator.Metric{Name: n.OTEL, Unit: n.Unit, Type: n.Type.otlp()})
	if err != nil {
		panic(fmt.Sprintf("cannot derive Prometheus name for metric %q: %s", n.OTEL, err))
	}

	n.Prom = prom
	return n
}

var (
	NetworkFlow = metric(Name{
		Section: "obi.network.flow",
		OTEL:    "obi.network.flow.bytes",
		Unit:    "{bytes}",
		Type:    InstrumentCounter,
	})
	NetworkFlowPackets = metric(Name{
		Section: "obi.network.flow.packets",
		OTEL:    "obi.network.flow.packets",
		Unit:    "{packets}",
		Type:    InstrumentCounter,
	})
	NetworkInterZone = metric(Name{
		Section: "obi.network.inter.zone",
		OTEL:    "obi.network.inter.zone.bytes",
		Unit:    "{bytes}",
		Type:    InstrumentCounter,
	})
	HTTPServerRequestSize = metric(Name{
		Section: "http.server.request.body.size",
		OTEL:    "http.server.request.body.size",
		Unit:    "By",
		Type:    InstrumentHistogram,
	})
	HTTPServerResponseSize = metric(Name{
		Section: "http.server.response.body.size",
		OTEL:    "http.server.response.body.size",
		Unit:    "By",
		Type:    InstrumentHistogram,
	})
	HTTPClientRequestSize = metric(Name{
		Section: "http.client.request.body.size",
		OTEL:    "http.client.request.body.size",
		Unit:    "By",
		Type:    InstrumentHistogram,
	})
	HTTPClientResponseSize = metric(Name{
		Section: "http.client.response.body.size",
		OTEL:    "http.client.response.body.size",
		Unit:    "By",
		Type:    InstrumentHistogram,
	})
	HTTPServerDuration = metric(Name{
		Section: "http.server.request.duration",
		OTEL:    "http.server.request.duration",
		Unit:    "s",
		Type:    InstrumentHistogram,
	})
	HTTPClientDuration = metric(Name{
		Section: "http.client.request.duration",
		OTEL:    "http.client.request.duration",
		Unit:    "s",
		Type:    InstrumentHistogram,
	})
	RPCServerDuration = metric(Name{
		Section: "rpc.server.call.duration",
		OTEL:    "rpc.server.call.duration",
		Unit:    "s",
		Type:    InstrumentHistogram,
	})
	RPCClientDuration = metric(Name{
		Section: "rpc.client.call.duration",
		OTEL:    "rpc.client.call.duration",
		Unit:    "s",
		Type:    InstrumentHistogram,
	})
	DBClientDuration = metric(Name{
		Section: "db.client.operation.duration",
		OTEL:    "db.client.operation.duration",
		Unit:    "s",
		Type:    InstrumentHistogram,
	})
	DBServerDuration = metric(Name{
		Section: "db.server.operation.duration",
		OTEL:    "db.server.operation.duration",
		Unit:    "s",
		Type:    InstrumentHistogram,
	})
	MessagingPublishDuration = metric(Name{
		Section: "messaging.client.operation.duration",
		OTEL:    "messaging.client.operation.duration",
		Unit:    "s",
		Type:    InstrumentHistogram,
	})
	MessagingProcessDuration = metric(Name{
		Section: "messaging.process.duration",
		OTEL:    "messaging.process.duration",
		Unit:    "s",
		Type:    InstrumentHistogram,
	})
	GPUCudaKernelLaunchCalls = metric(Name{
		Section: "gpu.cuda.kernel.launch.calls",
		OTEL:    "gpu.cuda.kernel.launch.calls",
		Type:    InstrumentCounter,
	})
	GPUCudaGraphLaunchCalls = metric(Name{
		Section: "gpu.cuda.graph.launch.calls",
		OTEL:    "gpu.cuda.graph.launch.calls",
		Type:    InstrumentCounter,
	})
	GPUCudaKernelGridSize = metric(Name{
		Section: "gpu.cuda.kernel.grid.size",
		OTEL:    "gpu.cuda.kernel.grid.size",
		Unit:    "1",
		Type:    InstrumentHistogram,
	})
	GPUCudaKernelBlockSize = metric(Name{
		Section: "gpu.cuda.kernel.block.size",
		OTEL:    "gpu.cuda.kernel.block.size",
		Unit:    "1",
		Type:    InstrumentHistogram,
	})
	GPUCudaMemoryAllocations = metric(Name{
		Section: "gpu.cuda.memory.allocations",
		OTEL:    "gpu.cuda.memory.allocations",
		Unit:    "By",
		Type:    InstrumentCounter,
	})
	GPUCudaMemoryCopies = metric(Name{
		Section: "gpu.cuda.memory.copies",
		OTEL:    "gpu.cuda.memory.copies",
		Unit:    "By",
		Type:    InstrumentHistogram,
	})
	DNSLookupDuration = metric(Name{
		Section: "dns.lookup.duration",
		OTEL:    "dns.lookup.duration",
		Unit:    "s",
		Type:    InstrumentHistogram,
	})
	GenAIClientInputTokenUsage = metric(Name{
		Section: "gen_ai.client.token.usage.input",
		OTEL:    "gen_ai.client.token.usage",
		Unit:    "{token}",
		Type:    InstrumentHistogram,
	})
	GenAIClientOutputTokenUsage = metric(Name{
		Section: "gen_ai.client.token.usage.output",
		OTEL:    "gen_ai.client.token.usage",
		Unit:    "{token}",
		Type:    InstrumentHistogram,
	})
	GenAIClientOperationDuration = metric(Name{
		Section: "gen_ai.client.operation.duration",
		OTEL:    "gen_ai.client.operation.duration",
		Unit:    "s",
		Type:    InstrumentHistogram,
	})
	GoRuntimeMemoryLimit = metric(Name{
		Section: "go.memory.limit",
		OTEL:    "go.memory.limit",
		Unit:    "By",
		Type:    InstrumentUpDownCounter,
	})
	GoRuntimeMemoryGCGoal = metric(Name{
		Section: "go.memory.gc.goal",
		OTEL:    "go.memory.gc.goal",
		Unit:    "By",
		Type:    InstrumentUpDownCounter,
	})
	GoRuntimeMemoryGCCycles = metric(Name{
		Section: "go.memory.gc.cycles",
		OTEL:    "go.memory.gc.cycles",
		Unit:    "{gc_cycle}",
		Type:    InstrumentCounter,
	})
	GoRuntimeMemoryGCPauseDuration = metric(Name{
		Section: "go.memory.gc.pause.duration",
		OTEL:    "go.memory.gc.pause.duration",
		Unit:    "s",
		Type:    InstrumentHistogram,
	})
	GoRuntimeMemoryUsed = metric(Name{
		Section: "go.memory.used",
		OTEL:    "go.memory.used",
		Unit:    "By",
		Type:    InstrumentUpDownCounter,
	})
	GoRuntimeMemoryAllocated = metric(Name{
		Section: "go.memory.allocated",
		OTEL:    "go.memory.allocated",
		Unit:    "By",
		Type:    InstrumentCounter,
	})
	GoRuntimeMemoryAllocations = metric(Name{
		Section: "go.memory.allocations",
		OTEL:    "go.memory.allocations",
		Unit:    "{allocation}",
		Type:    InstrumentCounter,
	})
	GoRuntimeCPUTime = metric(Name{
		Section: "go.cpu.time",
		OTEL:    "go.cpu.time",
		Unit:    "s",
		Type:    InstrumentCounter,
	})
	GoRuntimeGoroutineCount = metric(Name{
		Section: "go.goroutine.count",
		OTEL:    "go.goroutine.count",
		Unit:    "{goroutine}",
		Type:    InstrumentUpDownCounter,
	})
	GoRuntimeProcessorLimit = metric(Name{
		Section: "go.processor.limit",
		OTEL:    "go.processor.limit",
		Unit:    "{thread}",
		Type:    InstrumentUpDownCounter,
	})
	GoRuntimeConfigGOGC = metric(Name{
		Section: "go.config.gogc",
		OTEL:    "go.config.gogc",
		Unit:    "%",
		Type:    InstrumentUpDownCounter,
	})
	GoRuntimeScheduleDuration = metric(Name{
		Section: "go.schedule.duration",
		OTEL:    "go.schedule.duration",
		Unit:    "s",
		Type:    InstrumentHistogram,
	})
	CPythonGCCollections = metric(Name{
		Section: "cpython.gc.collections",
		OTEL:    "cpython.gc.collections",
		Unit:    "{collection}",
		Type:    InstrumentCounter,
	})
	CPythonGCCollectedObjects = metric(Name{
		Section: "cpython.gc.collected_objects",
		OTEL:    "cpython.gc.collected_objects",
		Unit:    "{object}",
		Type:    InstrumentCounter,
	})
	CPythonGCUncollectableObjects = metric(Name{
		Section: "cpython.gc.uncollectable_objects",
		OTEL:    "cpython.gc.uncollectable_objects",
		Unit:    "{object}",
		Type:    InstrumentCounter,
	})
	JVMMemoryUsed = metric(Name{
		Section: "jvm.memory.used",
		OTEL:    "jvm.memory.used",
		Unit:    "By",
		Type:    InstrumentUpDownCounter,
	})
	JVMMemoryCommitted = metric(Name{
		Section: "jvm.memory.committed",
		OTEL:    "jvm.memory.committed",
		Unit:    "By",
		Type:    InstrumentUpDownCounter,
	})
	JVMMemoryLimit = metric(Name{
		Section: "jvm.memory.limit",
		OTEL:    "jvm.memory.limit",
		Unit:    "By",
		Type:    InstrumentUpDownCounter,
	})
	JVMMemoryUsedAfterLastGC = metric(Name{
		Section: "jvm.memory.used_after_last_gc",
		OTEL:    "jvm.memory.used_after_last_gc",
		Unit:    "By",
		Type:    InstrumentUpDownCounter,
	})
	JVMClassLoaded = metric(Name{
		Section: "jvm.class.loaded",
		OTEL:    "jvm.class.loaded",
		Unit:    "{class}",
		Type:    InstrumentCounter,
	})
	JVMClassUnloaded = metric(Name{
		Section: "jvm.class.unloaded",
		OTEL:    "jvm.class.unloaded",
		Unit:    "{class}",
		Type:    InstrumentCounter,
	})
	JVMClassCount = metric(Name{
		Section: "jvm.class.count",
		OTEL:    "jvm.class.count",
		Unit:    "{class}",
		Type:    InstrumentUpDownCounter,
	})
	JVMThreadCount = metric(Name{
		Section: "jvm.thread.count",
		OTEL:    "jvm.thread.count",
		Unit:    "{thread}",
		Type:    InstrumentUpDownCounter,
	})
	JVMCPUTime = metric(Name{
		Section: "jvm.cpu.time",
		OTEL:    "jvm.cpu.time",
		Unit:    "s",
		Type:    InstrumentCounter,
	})
	JVMCPUCount = metric(Name{
		Section: "jvm.cpu.count",
		OTEL:    "jvm.cpu.count",
		Unit:    "{cpu}",
		Type:    InstrumentUpDownCounter,
	})
	JVMCPURecentUtilization = metric(Name{
		Section: "jvm.cpu.recent_utilization",
		OTEL:    "jvm.cpu.recent_utilization",
		Unit:    "1",
		Type:    InstrumentGauge,
	})
	NodejsEventLoopTime = metric(Name{
		Section: "nodejs.eventloop.time",
		OTEL:    "nodejs.eventloop.time",
		Unit:    "s",
		Type:    InstrumentCounter,
	})
	NodejsEventLoopUtilization = metric(Name{
		Section: "nodejs.eventloop.utilization",
		OTEL:    "nodejs.eventloop.utilization",
		Unit:    "1",
		Type:    InstrumentGauge,
	})
	NodejsEventLoopDelayMin = metric(Name{
		Section: "nodejs.eventloop.delay.min",
		OTEL:    "nodejs.eventloop.delay.min",
		Unit:    "s",
		Type:    InstrumentGauge,
	})
	NodejsEventLoopDelayMax = metric(Name{
		Section: "nodejs.eventloop.delay.max",
		OTEL:    "nodejs.eventloop.delay.max",
		Unit:    "s",
		Type:    InstrumentGauge,
	})
	NodejsEventLoopDelayMean = metric(Name{
		Section: "nodejs.eventloop.delay.mean",
		OTEL:    "nodejs.eventloop.delay.mean",
		Unit:    "s",
		Type:    InstrumentGauge,
	})
	NodejsEventLoopDelayStddev = metric(Name{
		Section: "nodejs.eventloop.delay.stddev",
		OTEL:    "nodejs.eventloop.delay.stddev",
		Unit:    "s",
		Type:    InstrumentGauge,
	})
	NodejsEventLoopDelayP50 = metric(Name{
		Section: "nodejs.eventloop.delay.p50",
		OTEL:    "nodejs.eventloop.delay.p50",
		Unit:    "s",
		Type:    InstrumentGauge,
	})
	NodejsEventLoopDelayP90 = metric(Name{
		Section: "nodejs.eventloop.delay.p90",
		OTEL:    "nodejs.eventloop.delay.p90",
		Unit:    "s",
		Type:    InstrumentGauge,
	})
	NodejsEventLoopDelayP99 = metric(Name{
		Section: "nodejs.eventloop.delay.p99",
		OTEL:    "nodejs.eventloop.delay.p99",
		Unit:    "s",
		Type:    InstrumentGauge,
	})
	V8JSGCDuration = metric(Name{
		Section: "v8js.gc.duration",
		OTEL:    "v8js.gc.duration",
		Unit:    "s",
		Type:    InstrumentHistogram,
	})
	V8JSMemoryHeapLimit = metric(Name{
		Section: "v8js.memory.heap.limit",
		OTEL:    "v8js.memory.heap.limit",
		Unit:    "By",
		Type:    InstrumentUpDownCounter,
	})
	V8JSMemoryHeapUsed = metric(Name{
		Section: "v8js.memory.heap.used",
		OTEL:    "v8js.memory.heap.used",
		Unit:    "By",
		Type:    InstrumentUpDownCounter,
	})
	V8JSMemoryHeapSpaceAvailableSize = metric(Name{
		Section: "v8js.memory.heap.space.available_size",
		OTEL:    "v8js.memory.heap.space.available_size",
		Unit:    "By",
		Type:    InstrumentUpDownCounter,
	})
	V8JSMemoryHeapSpacePhysicalSize = metric(Name{
		Section: "v8js.memory.heap.space.physical_size",
		OTEL:    "v8js.memory.heap.space.physical_size",
		Unit:    "By",
		Type:    InstrumentUpDownCounter,
	})
	// Resource is not an instrument: it only names the attributes.select section
	// that selects resource attributes. It still goes through metric() so its
	// Prom and OTEL forms stay populated like every other entry.
	Resource = metric(Name{
		Section: "resource",
		OTEL:    "resource",
	})
	StatTCPRtt = metric(Name{
		Section: "obi.stat.tcp.rtt",
		OTEL:    "obi.stat.tcp.rtt",
		Unit:    "s",
		Type:    InstrumentHistogram,
	})
	StatTCPFailedConnections = metric(Name{
		Section: "obi.stat.tcp.failed.connections",
		OTEL:    "obi.stat.tcp.failed.connections",
		Type:    InstrumentCounter,
	})
	StatTCPRetransmits = metric(Name{
		Section: "obi.stat.tcp.retransmits",
		OTEL:    "obi.stat.tcp.retransmits",
		Type:    InstrumentCounter,
	})
	StatTCPIo = metric(Name{
		Section: "obi.stat.tcp.io",
		OTEL:    "obi.stat.tcp.io",
		Unit:    "By",
		Type:    InstrumentCounter,
	})
)

// normalizeMetric will facilitate the user-input in the attributes.enable section.
// The user can specify the Prometheus or OTEL notation, and can include or not
// the units and aggregations for the metrics. OBI will accept all the inputs
// as long as the metric name is recorgnisable.
func normalizeMetric(name Section) Section {
	nameStr := strings.ReplaceAll(string(name), "_", ".")
	for _, suffix := range []string{".ratio", ".bucket", ".sum", ".count", ".total"} {
		if strings.HasSuffix(nameStr, suffix) {
			nameStr = nameStr[:len(nameStr)-len(suffix)]
			break
		}
	}
	for _, suffix := range []string{".bytes", ".seconds"} {
		if strings.HasSuffix(nameStr, suffix) {
			nameStr = nameStr[:len(nameStr)-len(suffix)]
			break
		}
	}
	return Section(nameStr)
}

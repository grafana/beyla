// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes // import "go.opentelemetry.io/obi/pkg/export/attributes"

// InternalMetrics declares OBI's own internal ("meta") metrics, which describe OBI rather than
// the instrumented application. Declaring them here lets the Prometheus name be derived from the
// OTLP definition instead of being hand-written a second time in the internal Prometheus
// exporter.
//
// They are built from a prefix at call time rather than declared as package variables, because a
// component that vendors OBI can override attr.VendorPrefix, and package-variable initialization
// would run before it had the chance.
//
// Unlike the metrics in metric.go these are not user-selectable, so they carry no Section:
// nothing refers to them from an attributes.select group.
type InternalMetrics struct {
	TracerFlushes            Name
	OTELMetricExports        Name
	OTELMetricExportErrors   Name
	OTELTraceExports         Name
	OTELTraceExportErrors    Name
	InstrumentedProcesses    Name
	InstrumentationErrors    Name
	AvoidedServices          Name
	BuildInfo                Name
	BpfProbeLatency          Name
	BpfMapEntries            Name
	BpfMapMaxEntries         Name
	KubeCacheForwardLag      Name
	BpfNetworkIgnoredPackets Name
	BpfNetworkPackets        Name
	QueueCapacityRatio       Name
}

func NewInternalMetrics(prefix string) InternalMetrics {
	return InternalMetrics{
		TracerFlushes: metric(Name{
			OTEL: prefix + ".ebpf.tracer.flushes",
			Unit: "1",
			Type: InstrumentHistogram,
		}),
		OTELMetricExports: metric(Name{
			OTEL: prefix + ".otel.metric.exports",
			Type: InstrumentCounter,
		}),
		OTELMetricExportErrors: metric(Name{
			OTEL: prefix + ".otel.metric.export.errors",
			Type: InstrumentCounter,
		}),
		OTELTraceExports: metric(Name{
			OTEL: prefix + ".otel.trace.exports",
			Type: InstrumentCounter,
		}),
		OTELTraceExportErrors: metric(Name{
			OTEL: prefix + ".otel.trace.export.errors",
			Type: InstrumentCounter,
		}),
		InstrumentedProcesses: metric(Name{
			OTEL: prefix + ".instrumented.processes",
			Type: InstrumentUpDownCounter,
		}),
		InstrumentationErrors: metric(Name{
			OTEL: prefix + ".instrumentation.errors",
			Type: InstrumentCounter,
		}),
		AvoidedServices: metric(Name{
			OTEL: prefix + ".avoided.services",
			Type: InstrumentGauge,
		}),
		BuildInfo: metric(Name{
			OTEL: prefix + ".internal.build.info",
			Type: InstrumentGauge,
		}),
		BpfProbeLatency: metric(Name{
			OTEL: prefix + ".bpf.probe.latency",
			Unit: "s",
			Type: InstrumentHistogram,
		}),
		BpfMapEntries: metric(Name{
			OTEL: prefix + ".bpf.map.entries",
			Type: InstrumentGauge,
		}),
		BpfMapMaxEntries: metric(Name{
			OTEL: prefix + ".bpf.map.max_entries",
			Type: InstrumentGauge,
		}),
		KubeCacheForwardLag: metric(Name{
			OTEL: prefix + ".kube.cache.forward.lag",
			Unit: "s",
			Type: InstrumentHistogram,
		}),
		BpfNetworkIgnoredPackets: metric(Name{
			OTEL: prefix + ".bpf.network.ignored.packets",
			Unit: "{packet}",
			Type: InstrumentCounter,
		}),
		BpfNetworkPackets: metric(Name{
			OTEL: prefix + ".bpf.network.packets",
			Unit: "{packet}",
			Type: InstrumentCounter,
		}),
		QueueCapacityRatio: metric(Name{
			OTEL: prefix + ".queue.capacity.ratio",
			Unit: "1",
			Type: InstrumentGauge,
		}),
	}
}

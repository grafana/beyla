package extraattributes

import (
	"fmt"

	"github.com/prometheus/otlptranslator"

	attributes "go.opentelemetry.io/obi/pkg/export/attributes"
)

// Metric mirrors the unexported attributes.metric() constructor in OBI: it derives the
// Prometheus name of a metric from its OTLP definition, applying the same translation a
// collector re-exporting Beyla's OTLP metrics in Prometheus format does.
//
// Beyla needs its own copy because OBI exports neither the constructor nor the
// Instrument → otlptranslator.MetricType mapping, and every attributes.Name that Beyla
// defines here or overrides in pkg/beyla.OverrideOBIGlobalConfig must keep OTEL, Unit,
// Type and Prom consistent with each other: OBI's exporters declare the instrument unit
// from Name.Unit, so a hand-written Name that leaves Unit empty both emits a unitless
// OTLP instrument and makes the Prometheus name disagree with the derived one.
func Metric(n attributes.Name) attributes.Name {
	namer := otlptranslator.MetricNamer{WithMetricSuffixes: true}

	prom, err := namer.Build(otlptranslator.Metric{Name: n.OTEL, Unit: n.Unit, Type: otlpInstrument(n.Type)})
	if err != nil {
		panic(fmt.Sprintf("cannot derive Prometheus name for metric %q: %s", n.OTEL, err))
	}

	n.Prom = prom
	return n
}

// otlpInstrument replicates attributes.Instrument.otlp(), which is unexported upstream.
func otlpInstrument(i attributes.Instrument) otlptranslator.MetricType {
	switch i {
	case attributes.InstrumentCounter:
		return otlptranslator.MetricTypeMonotonicCounter
	case attributes.InstrumentUpDownCounter:
		return otlptranslator.MetricTypeNonMonotonicCounter
	case attributes.InstrumentGauge:
		return otlptranslator.MetricTypeGauge
	case attributes.InstrumentHistogram:
		return otlptranslator.MetricTypeHistogram
	default:
		return otlptranslator.MetricTypeUnknown
	}
}

var (
	ProcessCPUTime = Metric(attributes.Name{
		Section: "process.cpu.time",
		OTEL:    "process.cpu.time",
		Unit:    "s",
		Type:    attributes.InstrumentCounter,
	})
	ProcessCPUUtilization = Metric(attributes.Name{
		Section: "process.cpu.utilization",
		OTEL:    "process.cpu.utilization",
		Unit:    "1",
		Type:    attributes.InstrumentGauge,
	})
	ProcessMemoryUsage = Metric(attributes.Name{
		Section: "process.memory.usage",
		OTEL:    "process.memory.usage",
		Unit:    "By",
		Type:    attributes.InstrumentUpDownCounter,
	})
	ProcessMemoryVirtual = Metric(attributes.Name{
		Section: "process.memory.virtual",
		OTEL:    "process.memory.virtual",
		Unit:    "By",
		Type:    attributes.InstrumentUpDownCounter,
	})
	ProcessDiskIO = Metric(attributes.Name{
		Section: "process.disk.io",
		OTEL:    "process.disk.io",
		Unit:    "By",
		Type:    attributes.InstrumentCounter,
	})
	ProcessNetIO = Metric(attributes.Name{
		Section: "process.network.io",
		OTEL:    "process.network.io",
		Unit:    "By",
		Type:    attributes.InstrumentCounter,
	})
)

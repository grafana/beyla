package beyla

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/prometheus/otlptranslator"

	obibuildinfo "go.opentelemetry.io/obi/pkg/buildinfo"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	otel2 "go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/obi"

	"github.com/grafana/beyla/v3/pkg/buildinfo"
	"github.com/grafana/beyla/v3/pkg/export/otel"
	cfgutil "github.com/grafana/beyla/v3/pkg/helpers/config"
)

func FromOBI(c *obi.Config) *Config {
	cfg := &Config{}
	cfgutil.Convert(c, cfg, map[string]string{
		// Fields that do not exist in OBI Config are marked for skipping,
		// to avoid that convert panics,
		".obi":              cfgutil.SkipConversion,
		".TracesReceiver":   cfgutil.SkipConversion,
		".SigilExport":      cfgutil.SkipConversion,
		".Processes":        cfgutil.SkipConversion,
		".Grafana":          cfgutil.SkipConversion,
		".Topology":         cfgutil.SkipConversion,
		".Discovery.Survey": cfgutil.SkipConversion,
		".Injector":         cfgutil.SkipConversion,
	})
	return cfg
}

func (c *Config) AsOBI() *obi.Config {
	if c.obi == nil {
		obiCfg := &obi.Config{}
		cfgutil.Convert(c, obiCfg, map[string]string{
			// here, some hints might be useful if we need to skip values that are non-existing in Beyla Config,
			// or, renamed. For example:
			// ".Some.Renamed.FieldInDst": "NameInSrc",
			// ".Some.Missing.FieldInSrc": cfgutil.SkipConversion,
		})
		overrideOBI(c, obiCfg)
		c.obi = obiCfg
	}
	return c.obi
}

// overrideOBI contains some extra tweaking that are required in the destination OBI configuration,
// to override some behaviors such as letting the OTEL exporters to adopt the Grafana credentials
func overrideOBI(src *Config, dst *obi.Config) {
	// metrics && traces endpoints
	if src.Grafana.OTLP.MetricsEnabled() {
		dst.OTELMetrics.OTLPEndpointProvider = func() (string, bool) {
			return otel.ResolveOTLPEndpoint(src.OTELMetrics.MetricsEndpoint, src.OTELMetrics.CommonEndpoint, &src.Grafana.OTLP)
		}
		dst.OTELMetrics.InjectHeaders = src.Grafana.OTLP.OverrideHeaders
	}
	if src.Grafana.OTLP.TracesEnabled() {
		dst.Traces.OTLPEndpointProvider = func() (string, bool) {
			return otel.ResolveOTLPEndpoint(src.Traces.TracesEndpoint, src.Traces.CommonEndpoint, &src.Grafana.OTLP)
		}
		dst.Traces.InjectHeaders = src.Grafana.OTLP.OverrideHeaders
	}
}

// OverrideOBIGlobalConfig overrides some OBI globals to adapt it to the Beyla configuration and naming conventions:
// - duplicates any BEYLA_ prefixed environment variables with the OTEL_EBPF_ prefix
// - overrides some custom global variables related to custom metric naming
func OverrideOBIGlobalConfig() {
	replacingPrefix := regexp.MustCompile("^BEYLA_(OTEL_)?")
	for _, env := range os.Environ() {
		newEnv := replacingPrefix.ReplaceAllString(env, "OTEL_EBPF_")
		if parts := strings.SplitN(newEnv, "=", 2); len(parts) == 2 {
			if os.Getenv(parts[0]) == "" {
				// Set only if not already set
				os.Setenv(parts[0], parts[1])
			}
		}
	}
	// Override global metric naming options
	obibuildinfo.Version = buildinfo.Version
	obibuildinfo.Revision = buildinfo.Revision
	otel2.CloudHostIDKey = "grafana_host_id"
	prom.CloudHostIDKey = "grafana_host_id"

	attr.VendorPrefix = "beyla"
	attr.VendorSDKName = "beyla"
	attr.OBIIP = "beyla.ip"
	attributes.NetworkFlow = beylaMetric(attributes.Name{
		Section: "beyla.network.flow",
		OTEL:    "beyla.network.flow.bytes",
		Unit:    "{bytes}",
		Type:    attributes.InstrumentCounter,
	})
	attributes.NetworkFlowPackets = beylaMetric(attributes.Name{
		Section: "beyla.network.flow.packets",
		OTEL:    "beyla.network.flow.packets",
		Unit:    "{packets}",
		Type:    attributes.InstrumentCounter,
	})
	attributes.NetworkInterZone = beylaMetric(attributes.Name{
		Section: "beyla.network.inter.zone",
		OTEL:    "beyla.network.inter.zone.bytes",
		Unit:    "{bytes}",
		Type:    attributes.InstrumentCounter,
	})
	attributes.StatTCPRtt = beylaMetric(attributes.Name{
		Section: "beyla.stat.tcp.rtt",
		OTEL:    "beyla.stat.tcp.rtt",
		Unit:    "s",
		Type:    attributes.InstrumentHistogram,
	})
	attributes.StatTCPFailedConnections = beylaMetric(attributes.Name{
		Section: "beyla.stat.tcp.failed.connections",
		OTEL:    "beyla.stat.tcp.failed.connections",
		Type:    attributes.InstrumentCounter,
	})
	attributes.StatTCPRetransmits = beylaMetric(attributes.Name{
		Section: "beyla.stat.tcp.retransmits",
		OTEL:    "beyla.stat.tcp.retransmits",
		Type:    attributes.InstrumentCounter,
	})
	attributes.StatTCPIo = beylaMetric(attributes.Name{
		Section: "beyla.stat.tcp.io",
		OTEL:    "beyla.stat.tcp.io",
		Unit:    "By",
		Type:    attributes.InstrumentCounter,
	})
}

// beylaMetric mirrors the unexported attributes.metric() constructor in OBI: it derives the
// Prometheus name from the OTLP definition (name + unit + instrument type), so that Beyla's
// Prometheus exporter and any collector re-exporting Beyla's OTLP output name the metric
// identically. OBI documents Name.Prom as "Derived, never set by hand", so the Beyla renames
// above must go through this instead of hardcoding the Prometheus name.
func beylaMetric(n attributes.Name) attributes.Name {
	namer := otlptranslator.MetricNamer{WithMetricSuffixes: true}

	prom, err := namer.Build(otlptranslator.Metric{Name: n.OTEL, Unit: n.Unit, Type: otlpInstrumentType(n.Type)})
	if err != nil {
		panic(fmt.Sprintf("cannot derive Prometheus name for metric %q: %s", n.OTEL, err))
	}

	n.Prom = prom
	return n
}

// otlpInstrumentType mirrors attributes.Instrument.otlp(), which OBI does not export.
func otlpInstrumentType(i attributes.Instrument) otlptranslator.MetricType {
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

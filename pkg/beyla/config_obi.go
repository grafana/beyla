package beyla

import (
	"os"
	"regexp"
	"strings"

	obibuildinfo "go.opentelemetry.io/obi/pkg/buildinfo"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	otel2 "go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/obi"

	"github.com/grafana/beyla/v3/pkg/buildinfo"
	"github.com/grafana/beyla/v3/pkg/export/extraattributes"
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
	// Unit and Type must be kept in sync with OBI's own definitions in
	// pkg/export/attributes/metric.go: OBI's exporters declare the OTLP instrument unit
	// from Name.Unit, and extraattributes.Metric derives Prom from OTEL+Unit+Type the
	// same way OBI does, so the Prometheus exporter and any Prometheus consumer of
	// Beyla's OTLP output name each metric identically.
	attributes.NetworkFlow = extraattributes.Metric(attributes.Name{
		Section: "beyla.network.flow",
		OTEL:    "beyla.network.flow.bytes",
		Unit:    "{bytes}",
		Type:    attributes.InstrumentCounter,
	})
	attributes.NetworkFlowPackets = extraattributes.Metric(attributes.Name{
		Section: "beyla.network.flow.packets",
		OTEL:    "beyla.network.flow.packets",
		Unit:    "{packets}",
		Type:    attributes.InstrumentCounter,
	})
	attributes.NetworkInterZone = extraattributes.Metric(attributes.Name{
		Section: "beyla.network.inter.zone",
		OTEL:    "beyla.network.inter.zone.bytes",
		Unit:    "{bytes}",
		Type:    attributes.InstrumentCounter,
	})
	attributes.StatTCPRtt = extraattributes.Metric(attributes.Name{
		Section: "beyla.stat.tcp.rtt",
		OTEL:    "beyla.stat.tcp.rtt",
		Unit:    "s",
		Type:    attributes.InstrumentHistogram,
	})
	attributes.StatTCPFailedConnections = extraattributes.Metric(attributes.Name{
		Section: "beyla.stat.tcp.failed.connections",
		OTEL:    "beyla.stat.tcp.failed.connections",
		Type:    attributes.InstrumentCounter,
	})
	attributes.StatTCPRetransmits = extraattributes.Metric(attributes.Name{
		Section: "beyla.stat.tcp.retransmits",
		OTEL:    "beyla.stat.tcp.retransmits",
		Type:    attributes.InstrumentCounter,
	})
	attributes.StatTCPIo = extraattributes.Metric(attributes.Name{
		Section: "beyla.stat.tcp.io",
		OTEL:    "beyla.stat.tcp.io",
		Unit:    "By",
		Type:    attributes.InstrumentCounter,
	})
}

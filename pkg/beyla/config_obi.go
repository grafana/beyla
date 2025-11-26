package beyla

import (
	"os"
	"regexp"
	"strings"

	obibuildinfo "go.opentelemetry.io/obi/pkg/buildinfo"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/obi"

	"github.com/grafana/beyla/v2/pkg/buildinfo"
	"github.com/grafana/beyla/v2/pkg/export/otel"
	cfgutil "github.com/grafana/beyla/v2/pkg/helpers/config"
)

func FromOBI(c *obi.Config) *Config {
	cfg := &Config{}
	cfgutil.Convert(c, cfg, map[string]string{
		// Fields that do not exist in OBI Config are marked for skipping,
		// to avoid that convert panics,
		".obi":              cfgutil.SkipConversion,
		".TracesReceiver":   cfgutil.SkipConversion,
		".Processes":        cfgutil.SkipConversion,
		".Grafana":          cfgutil.SkipConversion,
		".Topology":         cfgutil.SkipConversion,
		".Discovery.Survey": cfgutil.SkipConversion,
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
		normalizeOBIConfig(obiCfg)
		c.obi = obiCfg
	}
	return c.obi
}

// normalizeConfig normalizes user input to a common set of assumptions that are global to OBI
// TODO: this replicates a private function in OBI repo. We should make it public and invoke it here instead.
func normalizeOBIConfig(c *obi.Config) {
	c.Attributes.Select.Normalize()
}

// overrideOBI contains some extra tweaking that are required in the destination OBI configuration,
// to override some behaviors such as letting the OTEL exporters to adopt the Grafana credentials
func overrideOBI(src *Config, dst *obi.Config) {
	// metrics && traces endpoints
	if src.Grafana.OTLP.MetricsEnabled() {
		dst.Metrics.OTLPEndpointProvider = func() (string, bool) {
			return otel.ResolveOTLPEndpoint(src.Metrics.MetricsEndpoint, src.Metrics.CommonEndpoint, &src.Grafana.OTLP)
		}
		dst.Metrics.InjectHeaders = src.Grafana.OTLP.OverrideHeaders
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
	attr.VendorPrefix = "beyla"
	attr.VendorSDKName = "beyla"
	attr.OBIIP = "beyla.ip"
	attributes.NetworkFlow = attributes.Name{
		Section: "beyla.network.flow",
		Prom:    "beyla_network_flow_bytes_total",
		OTEL:    "beyla.network.flow.bytes",
	}
	attributes.NetworkInterZone = attributes.Name{
		Section: "beyla.network.inter.zone",
		Prom:    "beyla_network_inter_zone_bytes_total",
		OTEL:    "beyla.network.inter.zone.bytes",
	}
}

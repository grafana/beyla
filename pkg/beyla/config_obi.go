package beyla

import (
	"os"
	"regexp"
	"strings"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/obi"

	"github.com/grafana/beyla/v2/pkg/export/otel"
	cfgutil "github.com/grafana/beyla/v2/pkg/helpers/config"
)

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
	// Temporary patch: Overrides telemetry_sdk_name in OBI until we are able
	// to provide OBI with a mechanism to override resource & metric attributes
	if ras := os.Getenv("OTEL_RESOURCE_ATTRIBUTES"); ras != "" {
		os.Setenv("OTEL_RESOURCE_ATTRIBUTES", ras+",telemetry.sdk.name=beyla")
	} else {
		os.Setenv("OTEL_RESOURCE_ATTRIBUTES", "telemetry.sdk.name=beyla")
	}
	// Override global metric naming options
	attr.VendorPrefix = "beyla"
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

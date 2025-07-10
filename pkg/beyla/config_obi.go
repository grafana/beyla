package beyla

import (
	"os"
	"regexp"
	"strings"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/obi"

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

// SetupOBIEnvVars duplicates any BEYLA_ prefixed environment variables with the OTEL_EBPF_ prefix
// and vice versa
func SetupOBIEnvVars() {
	replacingPrefix := regexp.MustCompile("^BEYLA_(OTEL_)?")
	for _, env := range os.Environ() {
		newEnv := replacingPrefix.ReplaceAllString(env, "OTEL_EBPF_")
		if parts := strings.SplitN(newEnv, "=", 2); len(parts) == 2 {
			if _, ok := os.LookupEnv(parts[0]); !ok {
				// Set only if not already set
				os.Setenv(parts[0], parts[1])
			}
		}
	}
}

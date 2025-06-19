package beyla

import (
	"os"
	"strings"

	obi "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/beyla"

	"github.com/grafana/beyla/v2/pkg/export/otel"
	cfgutil "github.com/grafana/beyla/v2/pkg/helpers/config"
)

func (c *Config) AsOBI() *obi.Config {
	if c.obi == nil {
		obiCfg := &obi.Config{}
		cfgutil.Convert(c, obiCfg, map[string]string{
			// here, some hints might be useful if we need to skip values that are non-existing in OBI,
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
	for _, env := range os.Environ() {
		appended := appendAlternateEnvVar(env, "BEYLA_", "OTEL_EBPF_")
		if !appended {
			appendAlternateEnvVar(env, "OTEL_EBPF_", "BEYLA_")
		}
	}
}

func appendAlternateEnvVar(env, oldPrefix, altPrefix string) bool {
	oldLen := len(oldPrefix)
	if len(env) > (oldLen+1) && strings.HasPrefix(env, oldPrefix) {
		eqIdx := strings.IndexByte(env, '=')
		if eqIdx > (oldLen + 1) {
			key := env[:eqIdx]
			val := env[eqIdx+1:]
			newKey := altPrefix + key[oldLen:]
			// Only set if not already set
			if os.Getenv(newKey) == "" {
				os.Setenv(newKey, val)
			}
			return true
		}
	}
	return false
}

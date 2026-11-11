package beyla

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const dynamicInstrumentationYAML = `
trace_printer: text
discovery:
  instrument:
    - open_ports: 8080
dynamic_instrumentation:
  enabled: true
  listen_address: 127.0.0.1:8089
  rules:
    - service:
        - target_pids: [123]
      patches:
        - class: org.apache.logging.log4j.core.lookup.JndiLookup
          method: lookup
          descriptor: "(Lorg/apache/logging/log4j/core/LogEvent;Ljava/lang/String;)Ljava/lang/String;"
          action: return
          value: "none"
          ttl: 30s
`

func TestConfig_DynamicInstrumentationPatchesReachOBI(t *testing.T) {
	cfg, err := LoadConfig(strings.NewReader(dynamicInstrumentationYAML))
	require.NoError(t, err)
	cfg.DynamicInstrumentationConfigPath = "/etc/beyla/config.yml"
	require.NoError(t, cfg.Validate())

	di := cfg.AsOBI().DynamicInstrumentation
	assert.True(t, di.IsEnabled())
	assert.Equal(t, "127.0.0.1:8089", di.ListenAddress)
	require.Len(t, di.Rules, 1)
	require.Len(t, di.Rules[0].Patches, 1)
	patch := di.Rules[0].Patches[0]
	assert.Equal(t, "org.apache.logging.log4j.core.lookup.JndiLookup", patch.Class)
	assert.Equal(t, "none", patch.Value)
	assert.Equal(t, 30*time.Second, patch.TTL)
	assert.Equal(t, "return", patch.Action)
	assert.Equal(t, "/etc/beyla/config.yml", cfg.AsOBI().DynamicInstrumentationConfigPath)
}

func TestConfig_DynamicInstrumentationIsOffByDefault(t *testing.T) {
	cfg, err := LoadConfig(strings.NewReader("trace_printer: text\ndiscovery:\n  instrument:\n    - open_ports: 8080\n"))
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
	assert.False(t, cfg.AsOBI().DynamicInstrumentation.IsEnabled())
}

func TestConfig_DynamicInstrumentationEnvVariables(t *testing.T) {
	t.Setenv("OTEL_EBPF_DYNAMIC_INSTRUMENTATION_ENABLED", "true")
	t.Setenv("OTEL_EBPF_DYNAMIC_INSTRUMENTATION_LISTEN_ADDRESS", "127.0.0.1:8089")
	cfg, err := LoadConfig(strings.NewReader("trace_printer: text\ndiscovery:\n  instrument:\n    - open_ports: 8080\n"))
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
	di := cfg.AsOBI().DynamicInstrumentation
	assert.True(t, di.IsEnabled())
	assert.Equal(t, "127.0.0.1:8089", di.ListenAddress)
}

func TestConfig_DynamicInstrumentationRejectsInvalidPatches(t *testing.T) {
	bad := strings.Replace(dynamicInstrumentationYAML, `action: return`, `action: throw`, 1)
	cfg, err := LoadConfig(strings.NewReader(bad))
	require.NoError(t, err)
	err = cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "action must be")
}

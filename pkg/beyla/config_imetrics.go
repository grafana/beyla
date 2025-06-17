package beyla

import "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/imetrics"

// structs in this file mimic OBI's imetrics.Config in .obi-src/pkg/imetrics/imetrics.go
// but replaces OTEL_EBPF_* env vars by BEYLA_* for backwards compatibility
type internalMetricsConfig struct {
	Prometheus internalPromConfig               `yaml:"prometheus,omitempty"`
	Exporter   imetrics.InternalMetricsExporter `yaml:"exporter,omitempty" env:"BEYLA_INTERNAL_METRICS_EXPORTER"`
}

type internalPromConfig struct {
	Port int    `yaml:"port,omitempty" env:"BEYLA_INTERNAL_METRICS_PROMETHEUS_PORT"`
	Path string `yaml:"path,omitempty" env:"BEYLA_INTERNAL_METRICS_PROMETHEUS_PATH"`
}

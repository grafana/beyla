package beyla

import (
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/imetrics"
)

// structs in this file mimic some structs in from OBI, replacing OTEL_EBPF_*
// by BEYLA_* for backwards compatibility

// mimic imetrics.Config in .obi-src/pkg/imetrics/imetrics.go
type InternalMetricsConfig struct {
	Prometheus InternalPromConfig               `yaml:"prometheus,omitempty"`
	Exporter   imetrics.InternalMetricsExporter `yaml:"exporter,omitempty" env:"BEYLA_INTERNAL_METRICS_EXPORTER"`
}

type InternalPromConfig struct {
	Port int    `yaml:"port,omitempty" env:"BEYLA_INTERNAL_METRICS_PROMETHEUS_PORT"`
	Path string `yaml:"path,omitempty" env:"BEYLA_INTERNAL_METRICS_PROMETHEUS_PATH"`
}

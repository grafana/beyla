package imetrics

// TODO: manage the case where Port or Path might coincide with export/prom values
type PrometheusExporter struct {
	Port int    `yaml:"port" env:"INTERNAL_PROMETHEUS_PORT"`
	Path string `yaml:"path" env:"INTERNAL_PROMETHEUS_PATH"`
}

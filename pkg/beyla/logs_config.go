package beyla

import (
	"time"

	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"

	cfgutil "github.com/grafana/beyla/v3/pkg/helpers/config"
)

// LogsConfig is the v1 configuration for exception log export.
// OBI fills otelcfg.LogsConfig from a config v2 logger_provider and gives the
// struct no YAML or environment tags. The exported fields match that struct,
// including the runtime hooks, so FromOBI and AsOBI copy them by name.
type LogsConfig struct {
	// LogsExport and InjectHeaders are set by config v2 or by an in-process
	// consumer. They are not v1 settings; the tags keep them on the struct so
	// conversion still round-trips them.
	LogsExport    otelcfg.LogsExportFunc  `yaml:"-" env:"-"`
	Endpoint      string                  `yaml:"endpoint" env:"BEYLA_OTLP_LOGS_ENDPOINT"`
	Protocol      otelcfg.Protocol        `yaml:"protocol" env:"BEYLA_OTLP_LOGS_PROTOCOL"`
	Compression   string                  `yaml:"compression" env:"BEYLA_OTLP_LOGS_COMPRESSION" validate:"omitempty,oneof=none gzip"`
	BatchMaxSize  int                     `yaml:"batch_max_size" env:"BEYLA_OTLP_LOGS_BATCH_MAX_SIZE"`
	QueueSize     int                     `yaml:"queue_size" env:"BEYLA_OTLP_LOGS_QUEUE_SIZE"`
	BatchTimeout  time.Duration           `yaml:"batch_timeout" env:"BEYLA_OTLP_LOGS_BATCH_TIMEOUT"`
	InjectHeaders func(map[string]string) `yaml:"-" env:"-"`
}

// Enabled reports whether exception logs have somewhere to go.
func (c LogsConfig) Enabled() bool {
	cfg := c.otel()
	return cfg.Enabled()
}

// Validate checks the settings with the same rules as otelcfg.LogsConfig.
func (c LogsConfig) Validate() error {
	cfg := c.otel()
	return cfg.Validate()
}

func (c LogsConfig) otel() otelcfg.LogsConfig {
	var dst otelcfg.LogsConfig
	cfgutil.Convert(&c, &dst, nil)
	return dst
}

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schema // import "go.opentelemetry.io/obi/internal/config/schema"

import (
	"fmt"

	"go.yaml.in/yaml/v3"

	"go.opentelemetry.io/obi/pkg/export/debug"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
)

// Daemon describes standalone daemon settings.
type Daemon struct {
	Logging         Logging         `yaml:"logging"`
	Profiling       Profiling       `yaml:"profiling"`
	Shutdown        Shutdown        `yaml:"shutdown"`
	InternalMetrics InternalMetrics `yaml:"internal_metrics"`
	Telemetry       DaemonTelemetry `yaml:"telemetry"`
}

// LogFormat describes daemon log encoding.
type LogFormat string

const (
	// LogFormatUnset leaves the default logging format unchanged.
	LogFormatUnset LogFormat = ""
	// LogFormatText emits plain text logs.
	LogFormatText LogFormat = "text"
	// LogFormatJSON emits JSON logs.
	LogFormatJSON LogFormat = "json"
)

// UnmarshalYAML parses and validates a daemon log format.
func (f *LogFormat) UnmarshalYAML(value *yaml.Node) error {
	return unmarshalEnum(value, "format", f, LogFormatUnset, LogFormatText, LogFormatJSON)
}

// ConfigFormat describes startup configuration log encoding.
type ConfigFormat string

const (
	// ConfigFormatUnset disables startup configuration logging.
	ConfigFormatUnset ConfigFormat = ""
	// ConfigFormatYAML emits the startup configuration as YAML.
	ConfigFormatYAML ConfigFormat = "yaml"
	// ConfigFormatJSON emits the startup configuration as JSON.
	ConfigFormatJSON ConfigFormat = "json"
)

// UnmarshalYAML parses and validates a startup configuration log format.
func (f *ConfigFormat) UnmarshalYAML(value *yaml.Node) error {
	return unmarshalEnum(value, "config_format", f, ConfigFormatUnset, ConfigFormatYAML, ConfigFormatJSON)
}

// Logging describes daemon logging settings.
type Logging struct {
	Format           LogFormat          `yaml:"format"`
	ConfigFormat     ConfigFormat       `yaml:"config_format"`
	DebugTraceOutput debug.TracePrinter `yaml:"debug_trace_output"`
}

// UnmarshalYAML validates daemon logging settings.
func (l *Logging) UnmarshalYAML(value *yaml.Node) error {
	if _, ok := mappingValue(value, "level"); ok {
		return fmt.Errorf("unsupported daemon logging field %q; use top-level log_level", "level")
	}
	type plain Logging
	return value.Decode((*plain)(l))
}

// Profiling describes daemon profiling settings.
type Profiling struct {
	Port int `yaml:"port"`
}

// Shutdown describes daemon shutdown settings.
type Shutdown struct {
	Timeout Duration `yaml:"timeout"`
}

// InternalMetrics describes daemon internal metrics export settings.
type InternalMetrics struct {
	Exporter   imetrics.InternalMetricsExporter `yaml:"exporter"`
	Prometheus InternalPrometheus               `yaml:"prometheus"`
	BPF        BPFInternalMetrics               `yaml:"bpf"`
}

// InternalPrometheus describes the internal Prometheus metrics endpoint.
type InternalPrometheus struct {
	Port int    `yaml:"port"`
	Path string `yaml:"path"`
}

// BPFInternalMetrics describes internal BPF metrics scraping settings.
type BPFInternalMetrics struct {
	ScrapeInterval Duration `yaml:"scrape_interval"`
}

// DaemonTelemetry describes daemon telemetry settings.
type DaemonTelemetry struct {
	Metrics DaemonTelemetryMetrics `yaml:"metrics"`
}

// DaemonTelemetryMetrics describes daemon metric telemetry settings.
type DaemonTelemetryMetrics struct {
	Prometheus DaemonPrometheusTelemetry `yaml:"prometheus"`
}

// DaemonPrometheusTelemetry describes daemon Prometheus telemetry settings.
type DaemonPrometheusTelemetry struct {
	AllowServiceGraphSelfReferences bool     `yaml:"allow_service_graph_self_references"`
	SpanMetricsServiceCacheSize     int      `yaml:"span_metrics_service_cache_size"`
	ExtraResourceAttributes         []string `yaml:"extra_resource_attributes"`
	ExtraSpanResourceAttributes     []string `yaml:"extra_span_resource_attributes"`
}

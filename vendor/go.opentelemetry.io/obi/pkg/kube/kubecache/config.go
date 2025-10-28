// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kubecache

import (
	"fmt"
	"io"
	"time"

	"github.com/caarlos0/env/v9"
	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/instrument"
)

// Config options of the Kubernetes Cache service. Check the "DefaultConfig" variable for a view of the default values.
type Config struct {
	// LogLevel can be one of: debug, info, warn, error
	LogLevel string `yaml:"log_level" env:"OTEL_EBPF_K8S_CACHE_LOG_LEVEL"`
	// Port where the service is going to listen to
	Port int `yaml:"port" env:"OTEL_EBPF_K8S_CACHE_PORT"`
	// MaxConnection is the maximum number of concurrent clients that the service can handle at the same time
	MaxConnections int `yaml:"max_connections" env:"OTEL_EBPF_K8S_CACHE_MAX_CONNECTIONS"`
	// ProfilePort is the port where the pprof server is going to listen to. 0 (default) means disabled
	ProfilePort int `yaml:"profile_port" env:"OTEL_EBPF_K8S_CACHE_PROFILE_PORT"`
	// InformerResyncPeriod is the time interval between complete resyncs of the informers
	InformerResyncPeriod time.Duration `yaml:"informer_resync_period" env:"OTEL_EBPF_K8S_CACHE_INFORMER_RESYNC_PERIOD"`

	InternalMetrics instrument.InternalMetricsConfig `yaml:"internal_metrics"`
}

var DefaultConfig = Config{
	LogLevel:             "info",
	Port:                 50055,
	MaxConnections:       150,
	InformerResyncPeriod: 30 * time.Minute,
	ProfilePort:          0,
}

// LoadConfig overrides configuration in the following order (from less to most priority)
// 1 - Default configuration (DefaultConfig variable)
// 2 - Contents of the provided file reader (nillable)
// 3 - Environment variables
func LoadConfig(file io.Reader) (*Config, error) {
	cfg := DefaultConfig
	if file != nil {
		cfgBuf, err := io.ReadAll(file)
		if err != nil {
			return nil, fmt.Errorf("reading YAML configuration: %w", err)
		}
		// replaces environment variables in YAML file
		cfgBuf = config.ReplaceEnv(cfgBuf)
		if err := yaml.Unmarshal(cfgBuf, &cfg); err != nil {
			return nil, fmt.Errorf("parsing YAML configuration: %w", err)
		}
	}
	if err := env.Parse(&cfg); err != nil {
		return nil, fmt.Errorf("reading env vars: %w", err)
	}
	return &cfg, nil
}

package beyla

import (
	"go.opentelemetry.io/obi/pkg/appolly/services"

	cfgutil "github.com/grafana/beyla/v3/pkg/helpers/config"
)

// ExceptionsConfig is the v1 configuration for runtime exception capture.
// OBI accepts services.ExceptionsConfig only from config v2. The exported
// fields match that struct so FromOBI and AsOBI copy them by name.
type ExceptionsConfig struct {
	Enabled bool                        `yaml:"enabled" env:"BEYLA_EXCEPTIONS_ENABLED"`
	Go      services.GoExceptionsConfig `yaml:"go"`
}

func (c ExceptionsConfig) obi() services.ExceptionsConfig {
	var dst services.ExceptionsConfig
	cfgutil.Convert(&c, &dst, nil)
	return dst
}

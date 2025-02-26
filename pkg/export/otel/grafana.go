package otel

import (
	"encoding/base64"
	"fmt"
	"strings"
)

const (
	submitMetrics = "metrics"
	submitTraces  = "traces"
)

const (
	grafanaOTLP = "https://otlp-gateway-%s.grafana.net/otlp"
)

// GrafanaConfig simplifies the submission of information to Grafana Cloud, but it can
// be actually used for any OTEL endpoint, as it uses the standard OTEL authentication
// under the hood
type GrafanaConfig struct {
	// OTLP endpoint from Grafana Cloud.
	OTLP GrafanaOTLP `yaml:"otlp"`
}

type GrafanaOTLP struct {
	// Submit accepts a comma-separated list of the kind of data that will be submitted to the
	// OTLP endpoint. It accepts `metrics` and/or `traces` as values.
	Submit []string `yaml:"cloud_submit" env:"GRAFANA_CLOUD_SUBMIT"`

	// CloudZone of your Grafana Endpoint. For example: prod-eu-west-0.
	CloudZone string `yaml:"cloud_zone" env:"GRAFANA_CLOUD_ZONE"`

	// InstanceID is your Grafana user name. It is usually a number but it must be set as a
	// string inside the YAML file.
	InstanceID string `yaml:"cloud_instance_id" env:"GRAFANA_CLOUD_INSTANCE_ID"`

	// APIKey of your Grafana Cloud account.
	APIKey string `yaml:"cloud_api_key" env:"GRAFANA_CLOUD_API_KEY"`
}

func (cfg *GrafanaOTLP) MetricsEnabled() bool {
	return cfg.endpointEnabled() && cfg.submits(submitMetrics)
}

func (cfg *GrafanaOTLP) TracesEnabled() bool {
	return cfg.endpointEnabled() && cfg.submits(submitTraces)
}

func (cfg *GrafanaOTLP) endpointEnabled() bool {
	if cfg == nil {
		return false
	}
	// we could force an AND condition below, but the error could
	// remain unnoticed. This way, if the user forgets a field, they will
	// see an error log during the metrics submission
	return cfg.InstanceID != "" || cfg.APIKey != "" || cfg.CloudZone != ""
}

func (cfg *GrafanaOTLP) submits(s string) bool {
	if cfg == nil {
		return false
	}
	for _, sb := range cfg.Submit {
		if strings.ToLower(strings.TrimSpace(sb)) == s {
			return true
		}
	}
	return false
}

func (cfg *GrafanaOTLP) Endpoint() string {
	return fmt.Sprintf(grafanaOTLP, cfg.CloudZone)
}

func (cfg *GrafanaOTLP) AuthHeader() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(cfg.InstanceID+":"+cfg.APIKey))
}

func (cfg *GrafanaOTLP) HasAuth() bool {
	return cfg.InstanceID != "" && cfg.APIKey != ""
}

func (cfg *GrafanaOTLP) setupOptions(opt *otlpOptions) {
	if cfg == nil {
		return
	}
	if cfg.HasAuth() {
		if opt.Headers == nil {
			opt.Headers = map[string]string{}
		}
		opt.Headers["Authorization"] = cfg.AuthHeader()
	}
}

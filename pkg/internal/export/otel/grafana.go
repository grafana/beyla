package otel

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"
)

func gclog() *slog.Logger {
	return slog.With("component", "otel.GrafanaConfig")
}

const (
	submitMetrics = "metrics"
	submitTraces  = "traces"
)

const (
	grafanaOTLP = "https://otlp-gateway-%s.grafana.net/otlp"
)

// GrafanaConfig simplifies the submission of information to Grafana Cloud, but it can
// be actually used for any OTEl endpoint, as it uses the standard OTEL authentication
// under the hood
type GrafanaConfig struct {
	// OTLP endpoint from Grafana Cloud.
	OTLP GrafanaOTLP `yaml:"otlp"`
}

type GrafanaOTLP struct {
	// Submit accepts a comma-separated list of the kind of data that will be submit to the
	// OTLP endpoint. It accepts `metrics` and/or `traces` as values.
	Submit []string `yaml:"submit" env:"GRAFANA_OTLP_SUBMIT"`

	// CloudZone of your Grafana Endpoint. For example: prod-eu-west-0.
	CloudZone string `yaml:"cloud_zone" env:"GRAFANA_OTLP_CLOUD_ZONE"`

	// InstanceID is your Grafana user name. It is usually a number but it must be set as a
	// string inside the YAML file.
	InstanceID string `yaml:"instance_id" env:"GRAFANA_OTLP_CLOUD_INSTANCE_ID"`

	// APIKey of your Grafana Cloud account.
	APIKey string `yaml:"api_key" env:"GRAFANA_OTLP_CLOUD_API_KEY"`
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
	encodedKey := bytes.Buffer{}
	encodedKey.WriteString("Basic ")
	encoder := base64.NewEncoder(base64.StdEncoding, &encodedKey)
	_, err := encoder.Write([]byte(cfg.InstanceID + ":" + cfg.APIKey))
	if err != nil {
		// This should never happen, as the bytes.Buffer reader will never return error on Write
		gclog().Error("can't encode Grafana OTLP Authorization header. Leaving empty", "error", err)
		return ""
	}
	return encodedKey.String()
}

func (cfg *GrafanaOTLP) setupOptions(opt *otlpOptions) {
	if cfg == nil {
		return
	}
	if cfg.InstanceID != "" && cfg.APIKey != "" {
		if opt.HTTPHeaders == nil {
			opt.HTTPHeaders = map[string]string{}
		}
		opt.HTTPHeaders["Authorization"] = cfg.AuthHeader()
	}
}

package otel

import "time"

var timeNow = time.Now

const (
	SurveyInfo     = "survey_info"
	FeatureProcess = "application_process"
	ReporterName   = "github.com/grafana/beyla"
)

// ResolveOTLPEndpoint returns the OTLP endpoint, defined from one of the following sources, from highest to lowest priority
// - OTEL_EXPORTER_OTLP_METRICS_ENDPOINT, if defined
// - OTEL_EXPORTER_OTLP_ENDPOINT, if defined
// - https://otlp-gateway-${GRAFANA_CLOUD_ZONE}.grafana.net/otlp, if GRAFANA_CLOUD_ZONE is defined
// If, by some reason, Grafana changes its OTLP Gateway URL in a distant future, you can still point to the
// correct URL with the OTLP_EXPORTER_... variables.
// Returns true if the endpoint is common for both traces and metrics.
func ResolveOTLPEndpoint(endpoint, common string, grafana *GrafanaOTLP) (string, bool) {
	if endpoint != "" {
		return endpoint, false
	}

	if common != "" {
		return common, true
	}

	if grafana != nil && grafana.CloudZone != "" && grafana.Endpoint() != "" {
		return grafana.Endpoint(), true
	}

	return "", false
}

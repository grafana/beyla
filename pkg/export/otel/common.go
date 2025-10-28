package otel

import (
	"time"

	trace2 "go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

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

func SpanKind(span *request.Span) trace2.SpanKind {
	switch span.Type {
	case request.EventTypeHTTP, request.EventTypeGRPC, request.EventTypeRedisServer, request.EventTypeKafkaServer:
		return trace2.SpanKindServer
	case request.EventTypeHTTPClient, request.EventTypeGRPCClient, request.EventTypeSQLClient, request.EventTypeRedisClient, request.EventTypeMongoClient:
		return trace2.SpanKindClient
	case request.EventTypeKafkaClient:
		switch span.Method {
		case request.MessagingPublish:
			return trace2.SpanKindProducer
		case request.MessagingProcess:
			return trace2.SpanKindConsumer
		}
	}
	return trace2.SpanKindInternal
}

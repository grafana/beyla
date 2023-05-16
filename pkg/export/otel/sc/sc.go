package sc

import "go.opentelemetry.io/otel/attribute"

// HTTPResponseStatusCode is a temporary patch until the otel library is updated.
// TODO: use  semconv package as soon as a newer version of the library fixes the value according to the last version
// of the documentation:
// https://github.com/open-telemetry/opentelemetry-go/blob/main/semconv/v1.19.0/attribute_group.go#L41
// https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/metrics/semantic_conventions/http-metrics.md
var HTTPResponseStatusCode = attribute.Key("http.response.status_code")

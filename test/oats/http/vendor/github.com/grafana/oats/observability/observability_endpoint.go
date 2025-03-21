package observability

import (
	"context"

	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
)

type Endpoint interface {
	// Traces
	TracerProvider(context.Context, *resource.Resource) (*trace.TracerProvider, error)
	GetTraceByID(context.Context, string) ([]byte, error)
	SearchTags(context.Context, map[string]string) ([]byte, error)

	// Metrics
	RunPromQL(context.Context, string) ([]byte, error)

	Start(context.Context) error
	Stop(context.Context) error
}

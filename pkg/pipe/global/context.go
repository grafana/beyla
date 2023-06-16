package global

import (
	"context"

	"github.com/grafana/ebpf-autoinstrument/pkg/imetrics"

	"github.com/grafana/ebpf-autoinstrument/pkg/connector"
)

type contextInfoKey struct{}

// ContextInfo stores some context information that must be shared across some nodes of the
// processing graph, but it is not known during the instantiation time, so we
// set a pointer to this in the global context, then we write/read its properties
// from the different nodes
// TODO: generify and make this part of the github.com/mariomac/pipes library
type ContextInfo struct {
	// ReportRoutes sets whether the metrics should set the http.route attribute
	ReportRoutes bool
	// ServiceName is the value of the service.name metrics & span attribute
	ServiceName string
	// Metrics  that are internal to the pipe components
	Metrics imetrics.Reporter
	// Prometheus connection manager to coordinate metrics exposition from diverse nodes
	Prometheus connector.PrometheusManager
}

// SetContext creates a new context from the argument, storing the passed
// ContextInfo
func SetContext(ctx context.Context, info *ContextInfo) context.Context {
	return context.WithValue(ctx, contextInfoKey{}, info)
}

// Context gets the global ContextInfo associated to the passed context. It is used
// for some generic/dynamic functions that would require diverse passing of arguments.
// To avoid its misuse/abuse, this function should be only accessed from the Pipeline
// Graph node providers.
func Context(ctx context.Context) *ContextInfo {
	return ctx.Value(contextInfoKey{}).(*ContextInfo)
}

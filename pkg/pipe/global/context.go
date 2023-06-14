package global

import (
	"context"

	"github.com/grafana/ebpf-autoinstrument/pkg/connector"

	"github.com/grafana/ebpf-autoinstrument/pkg/imetrics"
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
	// Metrics internal to the pipe components
	Metrics imetrics.Reporter
	// Prometheus connection manager to manage metrics exposition from diverse nodes
	Prometheus connector.PrometheusManager
}

// SetContext creates a new context from the argument, storing the passed
// ContextInfo
func SetContext(ctx context.Context, info *ContextInfo) context.Context {
	return context.WithValue(ctx, contextInfoKey{}, info)
}

func Context(ctx context.Context) *ContextInfo {
	return ctx.Value(contextInfoKey{}).(*ContextInfo)
}

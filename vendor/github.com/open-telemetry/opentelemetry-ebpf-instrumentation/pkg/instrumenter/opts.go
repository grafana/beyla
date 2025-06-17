package instrumenter

import (
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/app/request"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/pipe/global"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
)

// Option that override the instantiation of the instrumenter
type Option func(info *global.ContextInfo)

// OverrideAppExportQueue allows to override the queue used to export the spans.
// This is useful to run the instrumenter in vendored mode, and you want to provide your
// own spans exporter.
// This queue will be used also by other bundled exported (OTEL, Prometheus...) if
// they are configured to run.
// See examples/vendoring/vendoring.go for an example of invocation.
func OverrideAppExportQueue(q *msg.Queue[[]request.Span]) Option {
	return func(info *global.ContextInfo) {
		info.OverrideAppExportQueue = q
	}
}

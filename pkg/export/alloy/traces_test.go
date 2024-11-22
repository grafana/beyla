package alloy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"

	"github.com/grafana/beyla/pkg/beyla"
	"github.com/grafana/beyla/pkg/export/attributes"
	"github.com/grafana/beyla/pkg/export/otel"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
)

func TestTracesSkipsInstrumented(t *testing.T) {
	svcNoExport := svc.Attrs{}

	svcNoExportTraces := svc.Attrs{}
	svcNoExportTraces.SetExportsOTelMetrics()

	svcExportTraces := svc.Attrs{}
	svcExportTraces.SetExportsOTelTraces()

	tests := []struct {
		name     string
		spans    []request.Span
		filtered bool
	}{
		{
			name:     "Foo span is not filtered",
			spans:    []request.Span{{Service: svcNoExport, Type: request.EventTypeHTTPClient, Method: "GET", Route: "/foo", RequestStart: 100, End: 200}},
			filtered: false,
		},
		{
			name:     "/v1/metrics span is not filtered",
			spans:    []request.Span{{Service: svcNoExportTraces, Type: request.EventTypeHTTPClient, Method: "GET", Route: "/v1/metrics", RequestStart: 100, End: 200}},
			filtered: false,
		},
		{
			name:     "/v1/traces span is filtered",
			spans:    []request.Span{{Service: svcExportTraces, Type: request.EventTypeHTTPClient, Method: "GET", Route: "/v1/traces", RequestStart: 100, End: 200}},
			filtered: true,
		},
	}

	tr := makeTracesTestReceiver()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			traces := generateTracesForSpans(t, tr, tt.spans)
			assert.Equal(t, tt.filtered, len(traces) == 0, tt.name)
		})
	}
}

func makeTracesTestReceiver() *tracesReceiver {
	return &tracesReceiver{
		ctx:        context.Background(),
		cfg:        &beyla.TracesReceiverConfig{},
		attributes: attributes.Selection{},
		hostID:     "Alloy",
	}
}

func generateTracesForSpans(t *testing.T, tr *tracesReceiver, spans []request.Span) []ptrace.Traces {
	res := []ptrace.Traces{}
	traceAttrs, err := otel.GetUserSelectedAttributes(tr.attributes)
	assert.NoError(t, err)
	for i := range spans {
		span := &spans[i]
		if tr.spanDiscarded(span) {
			continue
		}
		res = append(res, otel.GenerateTraces(span, tr.hostID, traceAttrs, []attribute.KeyValue{}))
	}

	return res
}

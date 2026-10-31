//go:build ignore

package integration

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/grafana/beyla/v3/internal/testgenerated/integration/components/jaeger"
)

// Jaeger can return a trace before all three Node.js servers have exported their spans.
func completeNodeJSTraces(traces []jaeger.Trace) []jaeger.Trace {
	var complete []jaeger.Trace
	for _, trace := range traces {
		if len(trace.FindByOperationName("GET /a", "server")) > 0 &&
			len(trace.FindByOperationName("GET /c", "server")) > 0 &&
			len(trace.FindByOperationName("GET /d", "server")) > 0 {
			complete = append(complete, trace)
		}
	}
	return complete
}

func TestCompleteNodeJSTraces(t *testing.T) {
	trace := func(id string, paths ...string) jaeger.Trace {
		result := jaeger.Trace{TraceID: id}
		for _, path := range paths {
			result.Spans = append(result.Spans, jaeger.Span{
				TraceID: id, OperationName: "GET " + path,
				Tags: []jaeger.Tag{
					{Key: "span.kind", Type: "string", Value: "server"},
					{Key: "url.path", Type: "string", Value: path},
				},
			})
		}
		return result
	}

	assert.Empty(t, completeNodeJSTraces(nil))
	assert.Empty(t, completeNodeJSTraces([]jaeger.Trace{trace("partial", "/a", "/c")}))
	complete := trace("complete", "/a", "/c", "/d")
	assert.Equal(t, []jaeger.Trace{complete}, completeNodeJSTraces([]jaeger.Trace{
		trace("partial", "/a"), complete,
	}))
}

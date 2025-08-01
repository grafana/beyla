package alloy

import (
	"context"
	"encoding/binary"
	"math/rand/v2"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	expirable2 "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/obi/pkg/app/request"
	"go.opentelemetry.io/obi/pkg/components/svc"
	attributes "go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/services"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/grafana/beyla/v2/pkg/beyla"
)

var cache = expirable2.NewLRU[svc.UID, []attribute.KeyValue](1024, nil, 5*time.Minute)

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

func TestTraceSkipSpanMetrics(t *testing.T) {
	spans := []request.Span{}
	start := time.Now()
	for i := 0; i < 10; i++ {
		span := request.Span{Type: request.EventTypeHTTP,
			RequestStart: start.UnixNano(),
			Start:        start.Add(time.Second).UnixNano(),
			End:          start.Add(3 * time.Second).UnixNano(),
			Method:       "GET",
			Route:        "/test" + strconv.Itoa(i),
			Status:       200,
			Service:      svc.Attrs{UID: svc.UID{Name: strconv.Itoa(i)}},
			TraceID:      randomTraceID(),
		}
		spans = append(spans, span)
	}

	t.Run("test with span metrics on", func(t *testing.T) {
		receiver := makeTracesTestReceiverWithSpanMetrics()

		traces := generateTracesForSpans(t, receiver, spans)
		assert.Equal(t, 10, len(traces))

		for _, ts := range traces {
			for i := 0; i < ts.ResourceSpans().Len(); i++ {
				rs := ts.ResourceSpans().At(i)
				for j := 0; j < rs.ScopeSpans().Len(); j++ {
					ss := rs.ScopeSpans().At(j)
					for k := 0; k < ss.Spans().Len(); k++ {
						span := ss.Spans().At(k)
						if strings.HasPrefix(span.Name(), "GET /test") {
							v, ok := span.Attributes().Get(string(attr.SkipSpanMetrics.OTEL()))
							assert.True(t, ok)
							assert.Equal(t, true, v.Bool())
						}
					}
				}
			}
		}
	})

	t.Run("test with span metrics off", func(t *testing.T) {
		receiver := makeTracesTestReceiver()

		traces := generateTracesForSpans(t, receiver, spans)
		assert.Equal(t, 10, len(traces))

		for _, ts := range traces {
			for i := 0; i < ts.ResourceSpans().Len(); i++ {
				rs := ts.ResourceSpans().At(i)
				for j := 0; j < rs.ScopeSpans().Len(); j++ {
					ss := rs.ScopeSpans().At(j)
					for k := 0; k < ss.Spans().Len(); k++ {
						span := ss.Spans().At(k)
						if strings.HasPrefix(span.Name(), "GET /test") {
							_, ok := span.Attributes().Get(string(attr.SkipSpanMetrics.OTEL()))
							assert.False(t, ok)
						}
					}
				}
			}
		}
	})
}

func TestTraceGrouping(t *testing.T) {
	spans := []request.Span{}
	start := time.Now()
	for i := 0; i < 10; i++ {
		span := request.Span{Type: request.EventTypeHTTP,
			RequestStart: start.UnixNano(),
			Start:        start.Add(time.Second).UnixNano(),
			End:          start.Add(3 * time.Second).UnixNano(),
			Method:       "GET",
			Route:        "/test" + strconv.Itoa(i),
			Status:       200,
			Service:      svc.Attrs{UID: svc.UID{Name: "1"}},
			TraceID:      randomTraceID(),
		}
		spans = append(spans, span)
	}

	t.Run("test span grouping", func(t *testing.T) {
		receiver := makeTracesTestReceiverWithSpanMetrics()

		traces := generateTracesForSpans(t, receiver, spans)
		assert.Equal(t, 1, len(traces))
	})
}

func TestTracesExportModeFiltering(t *testing.T) {
	start := time.Now()
	traceID := randomTraceID()

	// Service with no export modes (defaults to allowing all exports)
	svcDefault := svc.Attrs{
		UID: svc.UID{Name: "default-service"},
	}

	// Service explicitly configured to not export traces
	svcNoTraces := svc.Attrs{
		UID:         svc.UID{Name: "no-traces-service"},
		ExportModes: []services.ExportMode{services.ExportMetrics}, // Only metrics, no traces
	}

	// Service explicitly configured to export traces
	svcWithTraces := svc.Attrs{
		UID:         svc.UID{Name: "traces-service"},
		ExportModes: []services.ExportMode{services.ExportTraces, services.ExportMetrics},
	}

	tests := []struct {
		name           string
		service        svc.Attrs
		expectedTraces int
		description    string
	}{
		{
			name:           "Default service allows trace export",
			service:        svcDefault,
			expectedTraces: 1,
			description:    "Service with nil ExportModes should allow trace export",
		},
		{
			name:           "Service with no trace export mode filters traces",
			service:        svcNoTraces,
			expectedTraces: 0,
			description:    "Service configured to export only metrics should filter out traces",
		},
		{
			name:           "Service with trace export mode allows traces",
			service:        svcWithTraces,
			expectedTraces: 1,
			description:    "Service explicitly configured to export traces should allow trace export",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			span := request.Span{
				Type:         request.EventTypeHTTP,
				RequestStart: start.UnixNano(),
				Start:        start.Add(time.Second).UnixNano(),
				End:          start.Add(3 * time.Second).UnixNano(),
				Method:       "GET",
				Route:        "/test",
				Status:       200,
				Service:      tt.service,
				TraceID:      traceID,
			}

			// Create a mock consumer to capture traces
			mockConsumer := &mockTraceConsumer{}
			receiver := makeTracesTestReceiverWithConsumer(mockConsumer)

			// Test the actual provideLoop method
			testProvideLoopWithSpans(receiver, mockConsumer, []request.Span{span})

			assert.Equal(t, tt.expectedTraces, len(mockConsumer.getConsumedTraces()), tt.description)
		})
	}
}

// mockTraceConsumer captures traces for testing
type mockTraceConsumer struct {
	consumedTraces []ptrace.Traces
	mu             sync.Mutex
}

func (m *mockTraceConsumer) ConsumeTraces(ctx context.Context, traces ptrace.Traces) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.consumedTraces = append(m.consumedTraces, traces)
	return nil
}

func (m *mockTraceConsumer) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

func (m *mockTraceConsumer) getConsumedTraces() []ptrace.Traces {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]ptrace.Traces, len(m.consumedTraces))
	copy(result, m.consumedTraces)
	return result
}

func testProvideLoopWithSpans(receiver *tracesReceiver, mockConsumer *mockTraceConsumer, traces []request.Span) {
	// Create a channel to send traces to provideLoop
	tracesCh := make(chan []request.Span, 1)
	tracesCh <- traces
	close(tracesCh)

	// Set up the receiver input channel
	receiver.input = tracesCh

	// Run the provideLoop briefly
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	receiver.provideLoop(ctx)
}

func makeTracesTestReceiverWithConsumer(mockConsumer *mockTraceConsumer) *tracesReceiver {
	cfg := &beyla.TracesReceiverConfig{
		Traces:  []beyla.Consumer{mockConsumer},
		Sampler: services.SamplerConfig{}, // Set default sampler directly
	}

	return &tracesReceiver{
		cfg:    cfg,
		hostID: "Alloy",
		is: instrumentations.NewInstrumentationSelection([]string{
			instrumentations.InstrumentationALL,
		}),
		traceAttrs:     make(map[attr.Name]struct{}),
		attributeCache: expirable2.NewLRU[svc.UID, []attribute.KeyValue](1024, nil, 5*time.Minute),
	}
}

func makeTracesTestReceiver() *tracesReceiver {
	return &tracesReceiver{
		cfg:    &beyla.TracesReceiverConfig{},
		hostID: "Alloy",
		is: instrumentations.NewInstrumentationSelection([]string{
			instrumentations.InstrumentationALL,
		}),
	}
}

func makeTracesTestReceiverWithSpanMetrics() *tracesReceiver {
	return &tracesReceiver{
		cfg:                &beyla.TracesReceiverConfig{},
		hostID:             "Alloy",
		spanMetricsEnabled: true,
		is: instrumentations.NewInstrumentationSelection([]string{
			instrumentations.InstrumentationALL,
		}),
	}
}

func generateTracesForSpans(t *testing.T, tr *tracesReceiver, spans []request.Span) []ptrace.Traces {
	res := []ptrace.Traces{}
	err := tr.fetchConstantAttributes(&attributes.SelectorConfig{})
	assert.NoError(t, err)

	spanGroups := otel.GroupSpans(context.Background(), spans, tr.traceAttrs, sdktrace.AlwaysSample(), tr.is)
	for _, spanGroup := range spanGroups {
		if len(spanGroup) > 0 {
			sample := spanGroup[0]
			envResourceAttrs := otel.ResourceAttrsFromEnv(&sample.Span.Service)
			traces := otel.GenerateTraces(cache, &sample.Span.Service, envResourceAttrs, tr.hostID, spanGroup)
			res = append(res, traces)
		}
	}

	return res
}

func randomTraceID() trace.TraceID {
	t := trace.TraceID{}

	for i := 0; i < len(t); i += 4 {
		binary.LittleEndian.PutUint32(t[i:], rand.Uint32())
	}

	return t
}

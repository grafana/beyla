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
	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/tracesgen"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/export/otel"
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
		span := request.Span{
			Type:         request.EventTypeHTTP,
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
		span := request.Span{
			Type:         request.EventTypeHTTP,
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

	type tcConf struct {
		Exports services.ExportModes
	}

	var tcMetrics tcConf
	err := yaml.Unmarshal([]byte(`exports: ["metrics"]`), &tcMetrics)
	require.NoError(t, err)

	// Service explicitly configured to not export traces
	svcNoTraces := svc.Attrs{
		UID:         svc.UID{Name: "no-traces-service"},
		ExportModes: tcMetrics.Exports, // Only metrics, no traces
	}

	var tcBoth tcConf
	err = yaml.Unmarshal([]byte(`exports: ["metrics", "traces"]`), &tcBoth)
	require.NoError(t, err)

	// Service explicitly configured to export traces
	svcWithTraces := svc.Attrs{
		UID:         svc.UID{Name: "traces-service"},
		ExportModes: tcBoth.Exports,
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

func TestConnectTraces(t *testing.T) {
	mts := &mockTraceConsumer{}
	input := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	csr, err := ConnectionSpansReceiver(
		&global.ContextInfo{HostID: "the-host"},
		&beyla.Config{
			TracesReceiver: beyla.TracesReceiverConfig{
				Sampler:          services.SamplerConfig{Name: "always_on"},
				Traces:           []beyla.Consumer{mts},
				Instrumentations: []string{instrumentations.InstrumentationALL},
			},
		},
		input,
	)(t.Context())
	require.NoError(t, err)
	go csr(t.Context())

	require.Empty(t, mts.getConsumedTraces(), "No traces should be consumed yet")

	input.Send([]request.Span{{
		Type:     request.EventTypeHTTP,
		Method:   "GET",
		Route:    "/foo",
		Start:    123,
		End:      456,
		Service:  svc.Attrs{UID: svc.UID{Name: "foo"}},
		Host:     "1.2.3.4",
		HostName: "foo.com",
		Peer:     "4.2.3.1",
		PeerName: "4.2.3.1",
	}, {
		Type:     request.EventTypeHTTPClient,
		Method:   "POST",
		Route:    "/bar",
		Start:    321,
		End:      654,
		Service:  svc.Attrs{UID: svc.UID{Name: "foo"}},
		Host:     "1.2.3.4",
		HostName: "foo.com",
		Peer:     "3.3.2.6",
		PeerName: "3.3.2.6",
	}})

	test.Eventually(t, 5*time.Second, func(t require.TestingT) {
		require.NotEmpty(t, mts.getConsumedTraces())
	})
	grouped := mts.getConsumedTraces()
	require.Len(t, grouped, 1)

	group := grouped[0]
	require.Equal(t, 1, group.ResourceSpans().Len(),
		"both spans should have been recorded in the same resource")
	spans := group.ResourceSpans().At(0).ScopeSpans()
	require.Equal(t, 2, spans.Len(),
		"expected to have received two spans")
	span := spans.At(0).Spans()
	require.Equal(t, 1, span.Len())
	sp := span.At(0)
	assert.Equal(t, "GET /foo", sp.Name())
	assert.Equal(t, map[string]any{
		"client":         "4.2.3.1",
		"client.address": "4.2.3.1",
		"server":         "foo.com",
		"server.address": "foo.com",
		"beyla.topology": "external",
	}, sp.Attributes().AsRaw())

	span = spans.At(1).Spans()
	require.Equal(t, 1, span.Len())
	sp = span.At(0)
	assert.Equal(t, "POST /bar", sp.Name())
	assert.Equal(t, map[string]any{
		"server":         "foo.com",
		"server.address": "foo.com",
		"client":         "3.3.2.6",
		"client.address": "3.3.2.6",
		"beyla.topology": "external",
	}, sp.Attributes().AsRaw())
}

// mockTraceConsumer captures traces for testing
type mockTraceConsumer struct {
	consumedTraces []ptrace.Traces
	mu             sync.Mutex
}

func (m *mockTraceConsumer) ConsumeTraces(_ context.Context, traces ptrace.Traces) error {
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

func testProvideLoopWithSpans(receiver *tracesReceiver, _ *mockTraceConsumer, traces []request.Span) {
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

	spanGroups := tracesgen.GroupSpans(context.Background(), spans, tr.traceAttrs, sdktrace.AlwaysSample(), tr.is)
	for _, spanGroup := range spanGroups {
		if len(spanGroup) > 0 {
			sample := spanGroup[0]
			envResourceAttrs := otelcfg.ResourceAttrsFromEnv(&sample.Span.Service)
			traces := tracesgen.GenerateTracesWithAttributes(cache, &sample.Span.Service, envResourceAttrs, tr.hostID, spanGroup, otel.ReporterName)
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

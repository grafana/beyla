package otel

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/meta"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"

	"github.com/grafana/beyla/v3/pkg/internal/testutil"
	"github.com/grafana/beyla/v3/pkg/test/collector"
)

func clientSpanWithURL(scheme, host, path string, port int) request.Span {
	return request.Span{
		Type:      request.EventTypeHTTPClient,
		Method:    "GET",
		Route:     path,
		Path:      path,
		FullPath:  path,
		Statement: scheme + request.SchemeHostSeparator + host,
		Host:      host,
		HostName:  host,
		HostPort:  port,
		Peer:      "10.0.0.1",
		PeerName:  "client.local",
		Service:   svc.Attrs{UID: svc.UID{Name: "client-service"}},
		Start:     100,
		End:       200,
		SpanID:    [8]byte{9},
	}
}

func runConnectionSpan(t *testing.T, span request.Span) map[string]string {
	t.Helper()
	otlp, err := collector.Start(t.Context())
	require.NoError(t, err)
	traces := otlp.TraceRecords()

	input := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	cse, err := ConnectionSpansExport(
		&global.ContextInfo{NodeMeta: meta.NodeMeta{HostID: "the-host"}},
		&otelcfg.TracesConfig{
			TracesEndpoint: otlp.ServerEndpoint + "/v1/traces",
			TracesProtocol: otelcfg.ProtocolHTTPJSON,
			Instrumentations: []instrumentations.Instrumentation{
				instrumentations.InstrumentationALL,
			},
			SamplerConfig: services.SamplerConfig{Name: "always_on"},
			BatchMaxSize:  4096,
			BatchTimeout:  10 * time.Millisecond,
		},
		request.UnresolvedNames{},
		input,
	)(t.Context())
	require.NoError(t, err)
	go cse(t.Context())
	testutil.ChannelEmpty(t, traces, 10*time.Millisecond)

	input.Send([]request.Span{span})
	return testutil.ReadChannel(t, traces, 5*time.Second).Attributes
}

func TestConnection_Spans_URLFull(t *testing.T) {
	t.Run("scheme host port path", func(t *testing.T) {
		attrs := runConnectionSpan(t, clientSpanWithURL("https", "example.com", "/api/v1/users", 443))
		assert.Equal(t, "https://example.com:443/api/v1/users", attrs["url.full"])
	})

	t.Run("path with query string", func(t *testing.T) {
		span := clientSpanWithURL("http", "example.com", "/search?q=beyla&page=2", 8080)
		attrs := runConnectionSpan(t, span)
		assert.Equal(t, "http://example.com:8080/search?q=beyla&page=2", attrs["url.full"])
	})

	t.Run("ipv6 host without explicit port", func(t *testing.T) {
		span := clientSpanWithURL("http", "[2001:db8::1]", "/healthz", 0)
		attrs := runConnectionSpan(t, span)
		assert.Equal(t, "http://[2001:db8::1]/healthz", attrs["url.full"])
	})

	t.Run("non http client span emits no url.full", func(t *testing.T) {
		span := clientSpanWithURL("https", "example.com", "/api/v1/users", 443)
		span.Type = request.EventTypeHTTP
		attrs := runConnectionSpan(t, span)
		assert.NotContains(t, attrs, "url.full")
	})

	t.Run("missing scheme emits no url.full", func(t *testing.T) {
		span := clientSpanWithURL("https", "example.com", "/api/v1/users", 443)
		span.Statement = ""
		attrs := runConnectionSpan(t, span)
		assert.NotContains(t, attrs, "url.full")
	})

	t.Run("FullPath overrides Path", func(t *testing.T) {
		span := clientSpanWithURL("https", "example.com", "/route", 443)
		span.FullPath = "/actual/path?q=1"
		attrs := runConnectionSpan(t, span)
		assert.Equal(t, "https://example.com:443/actual/path?q=1", attrs["url.full"])
	})
}

func TestConnection_Spans(t *testing.T) {
	otlp, err := collector.Start(t.Context())
	require.NoError(t, err)
	traces := otlp.TraceRecords()

	input := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	cse, err := ConnectionSpansExport(
		&global.ContextInfo{NodeMeta: meta.NodeMeta{HostID: "the-host"}},
		&otelcfg.TracesConfig{
			TracesEndpoint: otlp.ServerEndpoint + "/v1/traces",
			TracesProtocol: otelcfg.ProtocolHTTPJSON,
			Instrumentations: []instrumentations.Instrumentation{
				instrumentations.InstrumentationALL,
			},
			SamplerConfig: services.SamplerConfig{Name: "always_on"},
			BatchMaxSize:  4096,
			BatchTimeout:  10 * time.Millisecond,
		},
		request.UnresolvedNames{},
		input,
	)(t.Context())
	require.NoError(t, err)
	go cse(t.Context())
	testutil.ChannelEmpty(t, traces, 10*time.Millisecond)

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
		SpanID:   [8]byte{2},
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
		SpanID:   [8]byte{1},
	}})

	trace := testutil.ReadChannel(t, traces, 5*time.Second)
	assert.Equal(t, "GET /foo", trace.Name)
	assert.Equal(t, map[string]string{
		"client":         "4.2.3.1",
		"client.address": "4.2.3.1",
		"server":         "foo.com",
		"server.address": "foo.com",
		"beyla.topology": "external",
		"parent_span_id": "",
		"span_id":        "0200000000000000",
	}, trace.Attributes)

	trace = testutil.ReadChannel(t, traces, 5*time.Second)
	assert.Equal(t, "POST /bar", trace.Name)
	assert.Equal(t, map[string]string{
		"server":         "foo.com",
		"server.address": "foo.com",
		"client":         "3.3.2.6",
		"client.address": "3.3.2.6",
		"beyla.topology": "external",
		"parent_span_id": "",
		"span_id":        "0100000000000000",
	}, trace.Attributes)
}

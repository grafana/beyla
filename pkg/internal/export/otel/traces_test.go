package otel

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/mariomac/pipes/pipe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.25.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/grafana/beyla/pkg/internal/export/attributes"
	attr "github.com/grafana/beyla/pkg/internal/export/attributes/names"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/sqlprune"
)

func TestHTTPTracesEndpoint(t *testing.T) {
	defer restoreEnvAfterExecution()()
	tcfg := TracesConfig{
		CommonEndpoint: "https://localhost:3131",
		TracesEndpoint: "https://localhost:3232/v1/traces",
	}

	t.Run("testing with two endpoints", func(t *testing.T) {
		testHTTPTracesOptions(t, otlpOptions{Endpoint: "localhost:3232", URLPath: "/v1/traces", HTTPHeaders: map[string]string{}}, &tcfg)
	})

	tcfg = TracesConfig{
		CommonEndpoint: "https://localhost:3131/otlp",
	}

	t.Run("testing with only common endpoint", func(t *testing.T) {
		testHTTPTracesOptions(t, otlpOptions{Endpoint: "localhost:3131", URLPath: "/otlp/v1/traces", HTTPHeaders: map[string]string{}}, &tcfg)
	})

	tcfg = TracesConfig{
		CommonEndpoint: "https://localhost:3131",
		TracesEndpoint: "http://localhost:3232",
	}
	t.Run("testing with insecure endpoint", func(t *testing.T) {
		testHTTPTracesOptions(t, otlpOptions{Endpoint: "localhost:3232", Insecure: true, HTTPHeaders: map[string]string{}}, &tcfg)
	})

	tcfg = TracesConfig{
		CommonEndpoint:     "https://localhost:3232",
		InsecureSkipVerify: true,
	}

	t.Run("testing with skip TLS verification", func(t *testing.T) {
		testHTTPTracesOptions(t, otlpOptions{Endpoint: "localhost:3232", URLPath: "/v1/traces", SkipTLSVerify: true, HTTPHeaders: map[string]string{}}, &tcfg)
	})
}

func TestHTTPTracesWithGrafanaOptions(t *testing.T) {
	defer restoreEnvAfterExecution()
	mcfg := TracesConfig{Grafana: &GrafanaOTLP{
		Submit:     []string{submitMetrics, submitTraces},
		CloudZone:  "eu-west-23",
		InstanceID: "12345",
		APIKey:     "affafafaafkd",
	}}
	t.Run("testing basic Grafana Cloud options", func(t *testing.T) {
		testHTTPTracesOptions(t, otlpOptions{
			Endpoint: "otlp-gateway-eu-west-23.grafana.net",
			URLPath:  "/otlp/v1/traces",
			HTTPHeaders: map[string]string{
				// Basic + output of: echo -n 12345:affafafaafkd | gbase64 -w 0
				"Authorization": "Basic MTIzNDU6YWZmYWZhZmFhZmtk",
			},
		}, &mcfg)
	})
	mcfg.CommonEndpoint = "https://localhost:3939"
	t.Run("Overriding endpoint URL", func(t *testing.T) {
		testHTTPTracesOptions(t, otlpOptions{
			Endpoint: "localhost:3939",
			URLPath:  "/v1/traces",
			HTTPHeaders: map[string]string{
				// Base64 representation of 12345:affafafaafkd
				"Authorization": "Basic MTIzNDU6YWZmYWZhZmFhZmtk",
			},
		}, &mcfg)
	})
}

func testHTTPTracesOptions(t *testing.T, expected otlpOptions, tcfg *TracesConfig) {
	defer restoreEnvAfterExecution()()
	opts, err := getHTTPTracesEndpointOptions(tcfg)
	require.NoError(t, err)
	assert.Equal(t, expected, opts)
}

func TestMissingSchemeInHTTPTracesEndpoint(t *testing.T) {
	defer restoreEnvAfterExecution()()
	opts, err := getHTTPTracesEndpointOptions(&TracesConfig{CommonEndpoint: "http://foo:3030"})
	require.NoError(t, err)
	require.NotEmpty(t, opts)

	_, err = getHTTPTracesEndpointOptions(&TracesConfig{CommonEndpoint: "foo:3030"})
	require.Error(t, err)

	_, err = getHTTPTracesEndpointOptions(&TracesConfig{CommonEndpoint: "foo"})
	require.Error(t, err)
}

func TestHTTPTracesEndpointHeaders(t *testing.T) {
	type testCase struct {
		Description     string
		Env             map[string]string
		ExpectedHeaders map[string]string
		Grafana         GrafanaOTLP
	}
	for _, tc := range []testCase{
		{Description: "No headers",
			ExpectedHeaders: map[string]string{}},
		{Description: "defining common OTLP_HEADERS",
			Env:             map[string]string{"OTEL_EXPORTER_OTLP_HEADERS": "Foo=Bar ==,Authorization=Base 2222=="},
			ExpectedHeaders: map[string]string{"Foo": "Bar ==", "Authorization": "Base 2222=="}},
		{Description: "defining common OTLP_TRACES_HEADERS",
			Env:             map[string]string{"OTEL_EXPORTER_OTLP_TRACES_HEADERS": "Foo=Bar ==,Authorization=Base 1234=="},
			ExpectedHeaders: map[string]string{"Foo": "Bar ==", "Authorization": "Base 1234=="}},
		{Description: "OTLP_TRACES_HEADERS takes precedence over OTLP_HEADERS",
			Env: map[string]string{
				"OTEL_EXPORTER_OTLP_HEADERS":        "Foo=Bar ==,Authorization=Base 3210==",
				"OTEL_EXPORTER_OTLP_TRACES_HEADERS": "Authorization=Base 1111==",
			},
			ExpectedHeaders: map[string]string{"Foo": "Bar ==", "Authorization": "Base 1111=="}},
		{Description: "Legacy Grafana Cloud vars",
			Grafana:         GrafanaOTLP{InstanceID: "123", APIKey: "456"},
			ExpectedHeaders: map[string]string{"Authorization": "Basic MTIzOjQ1Ng=="}},
		{Description: "OTLP en vars take precedence over legacy Grafana Cloud vars",
			Grafana:         GrafanaOTLP{InstanceID: "123", APIKey: "456"},
			Env:             map[string]string{"OTEL_EXPORTER_OTLP_HEADERS": "Foo=Bar ==,Authorization=Base 4321=="},
			ExpectedHeaders: map[string]string{"Foo": "Bar ==", "Authorization": "Base 4321=="},
		},
	} {
		// mutex to avoid running testcases in parallel so we don't mess up with env vars
		mt := sync.Mutex{}
		t.Run(fmt.Sprint(tc.Description), func(t *testing.T) {
			mt.Lock()
			restore := restoreEnvAfterExecution()
			defer func() {
				restore()
				mt.Unlock()
			}()
			for k, v := range tc.Env {
				require.NoError(t, os.Setenv(k, v))
			}

			opts, err := getHTTPTracesEndpointOptions(&TracesConfig{
				TracesEndpoint: "https://localhost:1234/v1/traces",
				Grafana:        &tc.Grafana,
			})
			require.NoError(t, err)
			assert.Equal(t, tc.ExpectedHeaders, opts.HTTPHeaders)
		})
	}
}

func TestGRPCTracesEndpointOptions(t *testing.T) {
	defer restoreEnvAfterExecution()()
	t.Run("do not accept URLs without a scheme", func(t *testing.T) {
		_, err := getGRPCTracesEndpointOptions(&TracesConfig{CommonEndpoint: "foo:3939"})
		assert.Error(t, err)
	})
	tcfg := TracesConfig{
		CommonEndpoint: "https://localhost:3131",
		TracesEndpoint: "https://localhost:3232",
	}

	t.Run("testing with two endpoints", func(t *testing.T) {
		testTracesGRPOptions(t, otlpOptions{Endpoint: "localhost:3232"}, &tcfg)
	})

	tcfg = TracesConfig{
		CommonEndpoint: "https://localhost:3131",
	}

	t.Run("testing with only common endpoint", func(t *testing.T) {
		testTracesGRPOptions(t, otlpOptions{Endpoint: "localhost:3131"}, &tcfg)
	})

	tcfg = TracesConfig{
		CommonEndpoint: "https://localhost:3131",
		TracesEndpoint: "http://localhost:3232",
	}
	t.Run("testing with insecure endpoint", func(t *testing.T) {
		testTracesGRPOptions(t, otlpOptions{Endpoint: "localhost:3232", Insecure: true}, &tcfg)
	})

	tcfg = TracesConfig{
		CommonEndpoint:     "https://localhost:3232",
		InsecureSkipVerify: true,
	}

	t.Run("testing with skip TLS verification", func(t *testing.T) {
		testTracesGRPOptions(t, otlpOptions{Endpoint: "localhost:3232", SkipTLSVerify: true}, &tcfg)
	})
}

func testTracesGRPOptions(t *testing.T, expected otlpOptions, tcfg *TracesConfig) {
	defer restoreEnvAfterExecution()()
	opts, err := getGRPCTracesEndpointOptions(tcfg)
	require.NoError(t, err)
	assert.Equal(t, expected, opts)
}

func TestTracesSetupHTTP_Protocol(t *testing.T) {
	testCases := []struct {
		Endpoint              string
		ProtoVal              Protocol
		TraceProtoVal         Protocol
		ExpectedProtoEnv      string
		ExpectedTraceProtoEnv string
	}{
		{ProtoVal: "", TraceProtoVal: "", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "http/protobuf"},
		{ProtoVal: "", TraceProtoVal: "foo", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "foo"},
		{ProtoVal: "bar", TraceProtoVal: "", ExpectedProtoEnv: "bar", ExpectedTraceProtoEnv: ""},
		{ProtoVal: "bar", TraceProtoVal: "foo", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "foo"},
		{Endpoint: "http://foo:4317", ProtoVal: "", TraceProtoVal: "", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "grpc"},
		{Endpoint: "http://foo:4317", ProtoVal: "", TraceProtoVal: "foo", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "foo"},
		{Endpoint: "http://foo:4317", ProtoVal: "bar", TraceProtoVal: "", ExpectedProtoEnv: "bar", ExpectedTraceProtoEnv: ""},
		{Endpoint: "http://foo:4317", ProtoVal: "bar", TraceProtoVal: "foo", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "foo"},
		{Endpoint: "http://foo:14317", ProtoVal: "", TraceProtoVal: "", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "grpc"},
		{Endpoint: "http://foo:14317", ProtoVal: "", TraceProtoVal: "foo", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "foo"},
		{Endpoint: "http://foo:14317", ProtoVal: "bar", TraceProtoVal: "", ExpectedProtoEnv: "bar", ExpectedTraceProtoEnv: ""},
		{Endpoint: "http://foo:14317", ProtoVal: "bar", TraceProtoVal: "foo", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "foo"},
		{Endpoint: "http://foo:4318", ProtoVal: "", TraceProtoVal: "", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "http/protobuf"},
		{Endpoint: "http://foo:4318", ProtoVal: "", TraceProtoVal: "foo", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "foo"},
		{Endpoint: "http://foo:4318", ProtoVal: "bar", TraceProtoVal: "", ExpectedProtoEnv: "bar", ExpectedTraceProtoEnv: ""},
		{Endpoint: "http://foo:4318", ProtoVal: "bar", TraceProtoVal: "foo", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "foo"},
		{Endpoint: "http://foo:24318", ProtoVal: "", TraceProtoVal: "", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "http/protobuf"},
		{Endpoint: "http://foo:24318", ProtoVal: "", TraceProtoVal: "foo", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "foo"},
		{Endpoint: "http://foo:24318", ProtoVal: "bar", TraceProtoVal: "", ExpectedProtoEnv: "bar", ExpectedTraceProtoEnv: ""},
		{Endpoint: "http://foo:24318", ProtoVal: "bar", TraceProtoVal: "foo", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "foo"},
	}
	for _, tc := range testCases {
		t.Run(tc.Endpoint+"/"+string(tc.ProtoVal)+"/"+string(tc.TraceProtoVal), func(t *testing.T) {
			defer restoreEnvAfterExecution()()
			_, err := getHTTPTracesEndpointOptions(&TracesConfig{
				CommonEndpoint: "http://host:3333",
				TracesEndpoint: tc.Endpoint,
				Protocol:       tc.ProtoVal,
				TracesProtocol: tc.TraceProtoVal,
			})
			require.NoError(t, err)
			assert.Equal(t, tc.ExpectedProtoEnv, os.Getenv(envProtocol))
			assert.Equal(t, tc.ExpectedTraceProtoEnv, os.Getenv(envTracesProtocol))
		})
	}
}

func TestTracesSetupHTTP_DoNotOverrideEnv(t *testing.T) {
	defer restoreEnvAfterExecution()()
	t.Run("setting both variables", func(t *testing.T) {
		defer restoreEnvAfterExecution()()
		require.NoError(t, os.Setenv(envProtocol, "foo-proto"))
		require.NoError(t, os.Setenv(envTracesProtocol, "bar-proto"))
		_, err := getHTTPTracesEndpointOptions(&TracesConfig{
			CommonEndpoint: "http://host:3333",
			Protocol:       "foo",
			TracesProtocol: "bar",
		})
		require.NoError(t, err)
		assert.Equal(t, "foo-proto", os.Getenv(envProtocol))
		assert.Equal(t, "bar-proto", os.Getenv(envTracesProtocol))
	})
	t.Run("setting only proto env var", func(t *testing.T) {
		defer restoreEnvAfterExecution()()
		require.NoError(t, os.Setenv(envProtocol, "foo-proto"))
		_, err := getHTTPTracesEndpointOptions(&TracesConfig{
			CommonEndpoint: "http://host:3333",
			Protocol:       "foo",
		})
		require.NoError(t, err)
		_, ok := os.LookupEnv(envTracesProtocol)
		assert.False(t, ok)
		assert.Equal(t, "foo-proto", os.Getenv(envProtocol))
	})
}

func TestGenerateTraces(t *testing.T) {
	t.Run("test with subtraces - with parent spanId", func(t *testing.T) {
		start := time.Now()
		parentSpanID, _ := trace.SpanIDFromHex("89cbc1f60aab3b04")
		spanID, _ := trace.SpanIDFromHex("89cbc1f60aab3b01")
		traceID, _ := trace.TraceIDFromHex("eae56fbbec9505c102e8aabfc6b5c481")
		span := &request.Span{
			Type:         request.EventTypeHTTP,
			RequestStart: start.UnixNano(),
			Start:        start.Add(time.Second).UnixNano(),
			End:          start.Add(3 * time.Second).UnixNano(),
			Method:       "GET",
			Route:        "/test",
			Status:       200,
			ParentSpanID: parentSpanID,
			TraceID:      traceID,
			SpanID:       spanID,
		}
		traces := GenerateTraces(span, map[attr.Name]struct{}{})

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 3, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
		assert.Equal(t, "in queue", spans.At(0).Name())
		assert.Equal(t, "processing", spans.At(1).Name())
		assert.Equal(t, "GET /test", spans.At(2).Name())
		assert.Equal(t, ptrace.SpanKindInternal, spans.At(0).Kind())
		assert.Equal(t, ptrace.SpanKindInternal, spans.At(1).Kind())
		assert.Equal(t, ptrace.SpanKindServer, spans.At(2).Kind())

		assert.NotEmpty(t, spans.At(2).SpanID().String())
		assert.Equal(t, traceID.String(), spans.At(2).TraceID().String())
		topSpanID := spans.At(2).SpanID().String()
		assert.Equal(t, parentSpanID.String(), spans.At(2).ParentSpanID().String())

		assert.NotEmpty(t, spans.At(0).SpanID().String())
		assert.Equal(t, traceID.String(), spans.At(0).TraceID().String())
		assert.Equal(t, topSpanID, spans.At(0).ParentSpanID().String())

		assert.Equal(t, spanID.String(), spans.At(1).SpanID().String())
		assert.Equal(t, traceID.String(), spans.At(1).TraceID().String())
		assert.Equal(t, topSpanID, spans.At(1).ParentSpanID().String())

		assert.NotEqual(t, spans.At(0).SpanID().String(), spans.At(1).SpanID().String())
		assert.NotEqual(t, spans.At(1).SpanID().String(), spans.At(2).SpanID().String())
	})

	t.Run("test with subtraces - ids set bpf layer", func(t *testing.T) {
		start := time.Now()
		spanID, _ := trace.SpanIDFromHex("89cbc1f60aab3b04")
		traceID, _ := trace.TraceIDFromHex("eae56fbbec9505c102e8aabfc6b5c481")
		span := &request.Span{
			Type:         request.EventTypeHTTP,
			RequestStart: start.UnixNano(),
			Start:        start.Add(time.Second).UnixNano(),
			End:          start.Add(3 * time.Second).UnixNano(),
			Method:       "GET",
			Route:        "/test",
			Status:       200,
			SpanID:       spanID,
			TraceID:      traceID,
		}
		traces := GenerateTraces(span, map[attr.Name]struct{}{})

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 3, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
		assert.Equal(t, "in queue", spans.At(0).Name())
		assert.Equal(t, "processing", spans.At(1).Name())
		assert.Equal(t, "GET /test", spans.At(2).Name())
		assert.Equal(t, ptrace.SpanKindInternal, spans.At(0).Kind())
		assert.Equal(t, ptrace.SpanKindInternal, spans.At(1).Kind())
		assert.Equal(t, ptrace.SpanKindServer, spans.At(2).Kind())

		assert.NotEmpty(t, spans.At(0).SpanID().String())
		assert.Equal(t, traceID.String(), spans.At(0).TraceID().String())

		assert.Equal(t, spanID.String(), spans.At(1).SpanID().String())
		assert.Equal(t, traceID.String(), spans.At(1).TraceID().String())

		assert.NotEmpty(t, spans.At(2).SpanID().String())
		assert.Equal(t, traceID.String(), spans.At(2).TraceID().String())
		assert.NotEqual(t, spans.At(0).SpanID().String(), spans.At(1).SpanID().String())
		assert.NotEqual(t, spans.At(1).SpanID().String(), spans.At(2).SpanID().String())
	})

	t.Run("test with subtraces - generated ids", func(t *testing.T) {
		start := time.Now()
		span := &request.Span{
			Type:         request.EventTypeHTTP,
			RequestStart: start.UnixNano(),
			Start:        start.Add(time.Second).UnixNano(),
			End:          start.Add(3 * time.Second).UnixNano(),
			Method:       "GET",
			Route:        "/test",
			Status:       200,
		}
		traces := GenerateTraces(span, map[attr.Name]struct{}{})

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 3, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
		assert.Equal(t, "in queue", spans.At(0).Name())
		assert.Equal(t, "processing", spans.At(1).Name())
		assert.Equal(t, "GET /test", spans.At(2).Name())
		assert.Equal(t, ptrace.SpanKindInternal, spans.At(0).Kind())
		assert.Equal(t, ptrace.SpanKindInternal, spans.At(1).Kind())
		assert.Equal(t, ptrace.SpanKindServer, spans.At(2).Kind())

		assert.NotEmpty(t, spans.At(0).SpanID().String())
		assert.NotEmpty(t, spans.At(0).TraceID().String())
		assert.NotEmpty(t, spans.At(1).SpanID().String())
		assert.NotEmpty(t, spans.At(1).TraceID().String())
		assert.NotEmpty(t, spans.At(2).SpanID().String())
		assert.NotEmpty(t, spans.At(2).TraceID().String())
		assert.NotEqual(t, spans.At(0).SpanID().String(), spans.At(1).SpanID().String())
		assert.NotEqual(t, spans.At(1).SpanID().String(), spans.At(2).SpanID().String())
	})

	t.Run("test without subspans - ids set bpf layer", func(t *testing.T) {
		start := time.Now()
		spanID, _ := trace.SpanIDFromHex("89cbc1f60aab3b04")
		traceID, _ := trace.TraceIDFromHex("eae56fbbec9505c102e8aabfc6b5c481")
		span := &request.Span{
			Type:         request.EventTypeHTTP,
			RequestStart: start.UnixNano(),
			End:          start.Add(3 * time.Second).UnixNano(),
			Method:       "GET",
			Route:        "/test",
			Status:       200,
			SpanID:       spanID,
			TraceID:      traceID,
		}
		traces := GenerateTraces(span, map[attr.Name]struct{}{})

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()

		assert.Equal(t, spanID.String(), spans.At(0).SpanID().String())
		assert.Equal(t, traceID.String(), spans.At(0).TraceID().String())
	})

	t.Run("test without subspans - with parent spanId", func(t *testing.T) {
		start := time.Now()
		parentSpanID, _ := trace.SpanIDFromHex("89cbc1f60aab3b04")
		traceID, _ := trace.TraceIDFromHex("eae56fbbec9505c102e8aabfc6b5c481")
		span := &request.Span{
			Type:         request.EventTypeHTTP,
			RequestStart: start.UnixNano(),
			End:          start.Add(3 * time.Second).UnixNano(),
			Method:       "GET",
			Route:        "/test",
			Status:       200,
			ParentSpanID: parentSpanID,
			TraceID:      traceID,
		}
		traces := GenerateTraces(span, map[attr.Name]struct{}{})

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()

		assert.Equal(t, parentSpanID.String(), spans.At(0).ParentSpanID().String())
		assert.Equal(t, traceID.String(), spans.At(0).TraceID().String())
	})

	t.Run("test without subspans - generated ids", func(t *testing.T) {
		start := time.Now()
		span := &request.Span{
			Type:         request.EventTypeHTTP,
			RequestStart: start.UnixNano(),
			End:          start.Add(3 * time.Second).UnixNano(),
			Method:       "GET",
			Route:        "/test",
		}
		traces := GenerateTraces(span, map[attr.Name]struct{}{})

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()

		assert.NotEmpty(t, spans.At(0).SpanID().String())
		assert.NotEmpty(t, spans.At(0).TraceID().String())
	})

}

func TestGenerateTracesAttributes(t *testing.T) {
	t.Run("test SQL trace generation, no statement", func(t *testing.T) {
		span := makeSQLRequestSpan("SELECT password FROM credentials WHERE username=\"bill\"")
		traces := GenerateTraces(&span, map[attr.Name]struct{}{})

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()

		assert.NotEmpty(t, spans.At(0).SpanID().String())
		assert.NotEmpty(t, spans.At(0).TraceID().String())

		attrs := spans.At(0).Attributes()

		assert.Equal(t, 5, attrs.Len())
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBOperation), "SELECT")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBCollectionName), "credentials")
		ensureTraceStrAttr(t, attrs, semconv.DBSystemKey, "other_sql")
		ensureTraceAttrNotExists(t, attrs, attribute.Key(attr.DBQueryText))
	})

	t.Run("test SQL trace generation, unknown attribute", func(t *testing.T) {
		span := makeSQLRequestSpan("SELECT password FROM credentials WHERE username=\"bill\"")
		traces := GenerateTraces(&span, map[attr.Name]struct{}{"db.operation.name": {}})

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()

		assert.NotEmpty(t, spans.At(0).SpanID().String())
		assert.NotEmpty(t, spans.At(0).TraceID().String())

		attrs := spans.At(0).Attributes()

		assert.Equal(t, 5, attrs.Len())
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBOperation), "SELECT")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBCollectionName), "credentials")
		ensureTraceStrAttr(t, attrs, semconv.DBSystemKey, "other_sql")
		ensureTraceAttrNotExists(t, attrs, attribute.Key(attr.DBQueryText))
	})

	t.Run("test SQL trace generation, unknown attribute", func(t *testing.T) {
		span := makeSQLRequestSpan("SELECT password FROM credentials WHERE username=\"bill\"")
		traces := GenerateTraces(&span, map[attr.Name]struct{}{attr.DBQueryText: {}})

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()

		assert.NotEmpty(t, spans.At(0).SpanID().String())
		assert.NotEmpty(t, spans.At(0).TraceID().String())

		attrs := spans.At(0).Attributes()

		assert.Equal(t, 6, attrs.Len())
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBOperation), "SELECT")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBCollectionName), "credentials")
		ensureTraceStrAttr(t, attrs, semconv.DBSystemKey, "other_sql")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBQueryText), "SELECT password FROM credentials WHERE username=\"bill\"")
	})
	t.Run("test Kafka trace generation", func(t *testing.T) {
		span := request.Span{Type: request.EventTypeKafkaClient, Method: "process", Path: "important-topic", OtherNamespace: "test"}
		traces := GenerateTraces(&span, map[attr.Name]struct{}{})

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()

		assert.NotEmpty(t, spans.At(0).SpanID().String())
		assert.NotEmpty(t, spans.At(0).TraceID().String())

		attrs := spans.At(0).Attributes()
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.MessagingOpType), "process")
		ensureTraceStrAttr(t, attrs, semconv.MessagingDestinationNameKey, "important-topic")
		ensureTraceStrAttr(t, attrs, semconv.MessagingClientIDKey, "test")

	})
}

func TestAttrsToMap(t *testing.T) {
	t.Run("test with string attribute", func(t *testing.T) {
		attrs := []attribute.KeyValue{
			attribute.String("key1", "value1"),
			attribute.String("key2", "value2"),
		}
		expected := pcommon.NewMap()
		expected.PutStr("key1", "value1")
		expected.PutStr("key2", "value2")

		result := attrsToMap(attrs)
		assert.Equal(t, expected, result)
	})

	t.Run("test with int attribute", func(t *testing.T) {
		attrs := []attribute.KeyValue{
			attribute.Int64("key1", 10),
			attribute.Int64("key2", 20),
		}
		expected := pcommon.NewMap()
		expected.PutInt("key1", 10)
		expected.PutInt("key2", 20)

		result := attrsToMap(attrs)
		assert.Equal(t, expected, result)
	})

	t.Run("test with float attribute", func(t *testing.T) {
		attrs := []attribute.KeyValue{
			attribute.Float64("key1", 3.14),
			attribute.Float64("key2", 2.718),
		}
		expected := pcommon.NewMap()
		expected.PutDouble("key1", 3.14)
		expected.PutDouble("key2", 2.718)

		result := attrsToMap(attrs)
		assert.Equal(t, expected, result)
	})

	t.Run("test with bool attribute", func(t *testing.T) {
		attrs := []attribute.KeyValue{
			attribute.Bool("key1", true),
			attribute.Bool("key2", false),
		}
		expected := pcommon.NewMap()
		expected.PutBool("key1", true)
		expected.PutBool("key2", false)

		result := attrsToMap(attrs)
		assert.Equal(t, expected, result)
	})
}

func TestCodeToStatusCode(t *testing.T) {
	t.Run("test with unset code", func(t *testing.T) {
		code := codes.Unset
		expected := ptrace.StatusCodeUnset

		result := codeToStatusCode(code)
		assert.Equal(t, expected, result)
	})

	t.Run("test with error code", func(t *testing.T) {
		code := codes.Error
		expected := ptrace.StatusCodeError

		result := codeToStatusCode(code)
		assert.Equal(t, expected, result)
	})

	t.Run("test with ok code", func(t *testing.T) {
		code := codes.Ok
		expected := ptrace.StatusCodeOk

		result := codeToStatusCode(code)
		assert.Equal(t, expected, result)
	})
}

func TestTraces_InternalInstrumentation(t *testing.T) {
	defer restoreEnvAfterExecution()()
	// fake OTEL collector server
	coll := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}))
	defer coll.Close()
	// Wait for the HTTP server to be alive
	test.Eventually(t, timeout, func(t require.TestingT) {
		resp, err := coll.Client().Get(coll.URL + "/foo")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
	builder := pipe.NewBuilder(&testPipeline{}, pipe.ChannelBufferLen(10))
	// create a simple dummy graph to send data to the Metrics reporter, which will send
	// metrics to the fake collector
	sendData := make(chan struct{}, 10)
	pipe.AddStart(builder, func(impl *testPipeline) *pipe.Start[[]request.Span] {
		return &impl.inputNode
	}, func(out chan<- []request.Span) {
		// on every send data signal, the traces generator sends a dummy trace
		for range sendData {
			out <- []request.Span{{Type: request.EventTypeHTTP}}
		}
	})
	internalTraces := &fakeInternalTraces{}
	pipe.AddFinalProvider(builder, func(impl *testPipeline) *pipe.Final[[]request.Span] {
		return &impl.exporter
	}, TracesReceiver(context.Background(),
		TracesConfig{
			CommonEndpoint:    coll.URL,
			BatchTimeout:      10 * time.Millisecond,
			ReportersCacheLen: 16,
		},
		&global.ContextInfo{
			Metrics: internalTraces,
		},
		attributes.Selection{},
	))
	graph, err := builder.Build()
	require.NoError(t, err)

	graph.Start()

	sendData <- struct{}{}
	var previousSum, previousCount int
	test.Eventually(t, timeout, func(t require.TestingT) {
		// we can't guarantee the number of calls at test time, but they must be at least 1
		previousSum, previousCount = internalTraces.SumCount()
		assert.LessOrEqual(t, 1, previousSum)
		assert.LessOrEqual(t, 1, previousCount)
		// the sum of metrics should be larger or equal than the number of calls (1 call : n metrics)
		assert.LessOrEqual(t, previousCount, previousSum)
		// no call should return error
		assert.Empty(t, internalTraces.Errors())
	})

	sendData <- struct{}{}
	// after some time, the number of calls should be higher than before
	test.Eventually(t, timeout, func(t require.TestingT) {
		sum, count := internalTraces.SumCount()
		assert.LessOrEqual(t, previousSum, sum)
		assert.LessOrEqual(t, previousCount, count)
		assert.LessOrEqual(t, count, sum)
		// no call should return error
		assert.Zero(t, internalTraces.Errors())
	})

	// collector starts failing, so errors should be received
	coll.CloseClientConnections()
	coll.Close()
	// Wait for the HTTP server to be stopped
	test.Eventually(t, timeout, func(t require.TestingT) {
		_, err := coll.Client().Get(coll.URL + "/foo")
		require.Error(t, err)
	})

	var previousErrCount int
	sendData <- struct{}{}
	test.Eventually(t, timeout, func(t require.TestingT) {
		previousSum, previousCount = internalTraces.SumCount()
		// calls should start returning errors
		previousErrCount = internalTraces.Errors()
		assert.NotZero(t, previousErrCount)
	})

	// after a while, metrics sum should not increase but errors do
	sendData <- struct{}{}
	test.Eventually(t, timeout, func(t require.TestingT) {
		sum, count := internalTraces.SumCount()
		assert.Equal(t, previousSum, sum)
		assert.Equal(t, previousCount, count)
		assert.Less(t, previousErrCount, internalTraces.Errors())
	})
}

func TestTraces_InternalInstrumentationSampling(t *testing.T) {
	defer restoreEnvAfterExecution()()
	// fake OTEL collector server
	coll := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}))
	defer coll.Close()
	// Wait for the HTTP server to be alive
	test.Eventually(t, timeout, func(t require.TestingT) {
		resp, err := coll.Client().Get(coll.URL + "/foo")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	builder := pipe.NewBuilder(&testPipeline{})
	// create a simple dummy graph to send data to the Metrics reporter, which will send
	// metrics to the fake collector
	sendData := make(chan struct{})
	pipe.AddStart(builder, func(impl *testPipeline) *pipe.Start[[]request.Span] {
		return &impl.inputNode
	}, func(out chan<- []request.Span) { // on every send data signal, the traces generator sends a dummy trace
		for range sendData {
			out <- []request.Span{{Type: request.EventTypeHTTP}}
		}
	})
	internalTraces := &fakeInternalTraces{}
	pipe.AddFinalProvider(builder, func(impl *testPipeline) *pipe.Final[[]request.Span] {
		return &impl.exporter
	}, TracesReceiver(context.Background(),
		TracesConfig{
			CommonEndpoint:    coll.URL,
			BatchTimeout:      10 * time.Millisecond,
			ExportTimeout:     5 * time.Second,
			Sampler:           Sampler{Name: "always_off"}, // we won't send any trace
			ReportersCacheLen: 16,
		},
		&global.ContextInfo{
			Metrics: internalTraces,
		},
		attributes.Selection{},
	))

	graph, err := builder.Build()
	require.NoError(t, err)

	graph.Start()

	// Let's make 10 traces, none should be seen
	for i := 0; i < 10; i++ {
		sendData <- struct{}{}
	}
	var previousSum, previousCount int
	test.Eventually(t, timeout, func(t require.TestingT) {
		// we shouldn't see any data
		previousSum, previousCount = internalTraces.SumCount()
		assert.Equal(t, 0, previousSum)
		assert.Equal(t, 0, previousCount)
		// no call should return error
		assert.Empty(t, internalTraces.Errors())
	})
}

func TestTracesConfig_Enabled(t *testing.T) {
	assert.True(t, TracesConfig{CommonEndpoint: "foo"}.Enabled())
	assert.True(t, TracesConfig{TracesEndpoint: "foo"}.Enabled())
	assert.True(t, TracesConfig{Grafana: &GrafanaOTLP{Submit: []string{"traces", "metrics"}, InstanceID: "33221"}}.Enabled())
}

func TestTracesConfig_Disabled(t *testing.T) {
	assert.False(t, TracesConfig{}.Enabled())
	assert.False(t, TracesConfig{Grafana: &GrafanaOTLP{Submit: []string{"metrics"}, InstanceID: "33221"}}.Enabled())
	assert.False(t, TracesConfig{Grafana: &GrafanaOTLP{Submit: []string{"traces"}}}.Enabled())
}

func TestSpanHostPeer(t *testing.T) {
	sp := request.Span{
		HostName: "localhost",
		Host:     "127.0.0.1",
		PeerName: "peerhost",
		Peer:     "127.0.0.2",
	}

	assert.Equal(t, "localhost", request.SpanHost(&sp))
	assert.Equal(t, "peerhost", request.SpanPeer(&sp))

	sp = request.Span{
		Host: "127.0.0.1",
		Peer: "127.0.0.2",
	}

	assert.Equal(t, "127.0.0.1", request.SpanHost(&sp))
	assert.Equal(t, "127.0.0.2", request.SpanPeer(&sp))

	sp = request.Span{}

	assert.Equal(t, "", request.SpanHost(&sp))
	assert.Equal(t, "", request.SpanPeer(&sp))
}

type fakeInternalTraces struct {
	imetrics.NoopReporter
	sum  atomic.Int32
	cnt  atomic.Int32
	errs atomic.Int32
}

func (f *fakeInternalTraces) OTELTraceExport(len int) {
	f.cnt.Add(1)
	f.sum.Add(int32(len))
}

func (f *fakeInternalTraces) OTELTraceExportError(_ error) {
	f.errs.Add(1)
}

func (f *fakeInternalTraces) Errors() int {
	return int(f.errs.Load())
}

func (f *fakeInternalTraces) SumCount() (sum, count int) {
	return int(f.sum.Load()), int(f.cnt.Load())
}

// stores the values of some modified env vars to avoid
// interferences between cases. Must be invoked as:
// defer restoreEnvAfterExecution()()
func restoreEnvAfterExecution() func() {
	vals := []*struct {
		name   string
		val    string
		exists bool
	}{
		{name: envTracesProtocol}, {name: envMetricsProtocol}, {name: envProtocol},
		{name: envHeaders}, {name: envTracesHeaders},
	}
	for _, v := range vals {
		v.val, v.exists = os.LookupEnv(v.name)
	}
	return func() {
		for _, v := range vals {
			if v.exists {
				os.Setenv(v.name, v.val)
			} else {
				os.Unsetenv(v.name)
			}
		}
	}
}

func TestTraces_HTTPStatus(t *testing.T) {
	type testPair struct {
		httpCode   int
		statusCode codes.Code
	}

	t.Run("HTTP server testing", func(t *testing.T) {
		for _, p := range []testPair{
			{100, codes.Unset},
			{103, codes.Unset},
			{199, codes.Unset},
			{200, codes.Unset},
			{204, codes.Unset},
			{299, codes.Unset},
			{300, codes.Unset},
			{399, codes.Unset},
			{400, codes.Unset},
			{404, codes.Unset},
			{405, codes.Unset},
			{499, codes.Unset},
			{500, codes.Error},
			{5999, codes.Error},
		} {
			assert.Equal(t, p.statusCode, request.HTTPSpanStatusCode(&request.Span{Status: p.httpCode, Type: request.EventTypeHTTP}))
			assert.Equal(t, p.statusCode, request.SpanStatusCode(&request.Span{Status: p.httpCode, Type: request.EventTypeHTTP}))
		}
	})

	t.Run("HTTP client testing", func(t *testing.T) {
		for _, p := range []testPair{
			{100, codes.Unset},
			{103, codes.Unset},
			{199, codes.Unset},
			{200, codes.Unset},
			{204, codes.Unset},
			{299, codes.Unset},
			{300, codes.Unset},
			{399, codes.Unset},
			{400, codes.Error},
			{404, codes.Error},
			{405, codes.Error},
			{499, codes.Error},
			{500, codes.Error},
			{5999, codes.Error},
		} {
			assert.Equal(t, p.statusCode, request.HTTPSpanStatusCode(&request.Span{Status: p.httpCode, Type: request.EventTypeHTTPClient}))
			assert.Equal(t, p.statusCode, request.SpanStatusCode(&request.Span{Status: p.httpCode, Type: request.EventTypeHTTPClient}))
		}
	})
}

func TestTraces_GRPCStatus(t *testing.T) {
	type testPair struct {
		grpcCode   attribute.KeyValue
		statusCode codes.Code
	}

	t.Run("gRPC server testing", func(t *testing.T) {
		for _, p := range []testPair{
			{semconv.RPCGRPCStatusCodeOk, codes.Unset},
			{semconv.RPCGRPCStatusCodeCancelled, codes.Unset},
			{semconv.RPCGRPCStatusCodeUnknown, codes.Error},
			{semconv.RPCGRPCStatusCodeInvalidArgument, codes.Unset},
			{semconv.RPCGRPCStatusCodeDeadlineExceeded, codes.Error},
			{semconv.RPCGRPCStatusCodeNotFound, codes.Unset},
			{semconv.RPCGRPCStatusCodeAlreadyExists, codes.Unset},
			{semconv.RPCGRPCStatusCodePermissionDenied, codes.Unset},
			{semconv.RPCGRPCStatusCodeResourceExhausted, codes.Unset},
			{semconv.RPCGRPCStatusCodeFailedPrecondition, codes.Unset},
			{semconv.RPCGRPCStatusCodeAborted, codes.Unset},
			{semconv.RPCGRPCStatusCodeOutOfRange, codes.Unset},
			{semconv.RPCGRPCStatusCodeUnimplemented, codes.Error},
			{semconv.RPCGRPCStatusCodeInternal, codes.Error},
			{semconv.RPCGRPCStatusCodeUnavailable, codes.Error},
			{semconv.RPCGRPCStatusCodeDataLoss, codes.Error},
			{semconv.RPCGRPCStatusCodeUnauthenticated, codes.Unset},
		} {
			assert.Equal(t, p.statusCode, request.GrpcSpanStatusCode(&request.Span{Status: int(p.grpcCode.Value.AsInt64()), Type: request.EventTypeGRPC}))
			assert.Equal(t, p.statusCode, request.SpanStatusCode(&request.Span{Status: int(p.grpcCode.Value.AsInt64()), Type: request.EventTypeGRPC}))
		}
	})

	t.Run("gRPC client testing", func(t *testing.T) {
		for _, p := range []testPair{
			{semconv.RPCGRPCStatusCodeOk, codes.Unset},
			{semconv.RPCGRPCStatusCodeCancelled, codes.Error},
			{semconv.RPCGRPCStatusCodeUnknown, codes.Error},
			{semconv.RPCGRPCStatusCodeInvalidArgument, codes.Error},
			{semconv.RPCGRPCStatusCodeDeadlineExceeded, codes.Error},
			{semconv.RPCGRPCStatusCodeNotFound, codes.Error},
			{semconv.RPCGRPCStatusCodeAlreadyExists, codes.Error},
			{semconv.RPCGRPCStatusCodePermissionDenied, codes.Error},
			{semconv.RPCGRPCStatusCodeResourceExhausted, codes.Error},
			{semconv.RPCGRPCStatusCodeFailedPrecondition, codes.Error},
			{semconv.RPCGRPCStatusCodeAborted, codes.Error},
			{semconv.RPCGRPCStatusCodeOutOfRange, codes.Error},
			{semconv.RPCGRPCStatusCodeUnimplemented, codes.Error},
			{semconv.RPCGRPCStatusCodeInternal, codes.Error},
			{semconv.RPCGRPCStatusCodeUnavailable, codes.Error},
			{semconv.RPCGRPCStatusCodeDataLoss, codes.Error},
			{semconv.RPCGRPCStatusCodeUnauthenticated, codes.Error},
		} {
			assert.Equal(t, p.statusCode, request.GrpcSpanStatusCode(&request.Span{Status: int(p.grpcCode.Value.AsInt64()), Type: request.EventTypeGRPCClient}))
			assert.Equal(t, p.statusCode, request.SpanStatusCode(&request.Span{Status: int(p.grpcCode.Value.AsInt64()), Type: request.EventTypeGRPCClient}))
		}
	})
}

func makeSQLRequestSpan(sql string) request.Span {
	method, path := sqlprune.SQLParseOperationAndTable(sql)
	return request.Span{Type: request.EventTypeSQLClient, Method: method, Path: path, Statement: sql}
}

func ensureTraceStrAttr(t *testing.T, attrs pcommon.Map, key attribute.Key, val string) {
	v, ok := attrs.Get(string(key))
	assert.True(t, ok)
	assert.Equal(t, val, v.AsString())
}

func ensureTraceAttrNotExists(t *testing.T, attrs pcommon.Map, key attribute.Key) {
	_, ok := attrs.Get(string(key))
	assert.False(t, ok)
}

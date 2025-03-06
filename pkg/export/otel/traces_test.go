package otel

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/mariomac/pipes/pipe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.25.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/grafana/beyla/v2/pkg/export/attributes"
	attr "github.com/grafana/beyla/v2/pkg/export/attributes/names"
	"github.com/grafana/beyla/v2/pkg/export/instrumentations"
	"github.com/grafana/beyla/v2/pkg/internal/imetrics"
	"github.com/grafana/beyla/v2/pkg/internal/pipe/global"
	"github.com/grafana/beyla/v2/pkg/internal/request"
	"github.com/grafana/beyla/v2/pkg/internal/sqlprune"
	"github.com/grafana/beyla/v2/pkg/internal/svc"
)

func TestHTTPTracesEndpoint(t *testing.T) {
	defer restoreEnvAfterExecution()()
	tcfg := TracesConfig{
		CommonEndpoint:   "https://localhost:3131",
		TracesEndpoint:   "https://localhost:3232/v1/traces",
		Instrumentations: []string{instrumentations.InstrumentationALL},
	}

	t.Run("testing with two endpoints", func(t *testing.T) {
		testHTTPTracesOptions(t, otlpOptions{Scheme: "https", Endpoint: "localhost:3232", URLPath: "/v1/traces", Headers: map[string]string{}}, &tcfg)
	})

	tcfg = TracesConfig{
		CommonEndpoint:   "https://localhost:3131/otlp",
		Instrumentations: []string{instrumentations.InstrumentationALL},
	}

	t.Run("testing with only common endpoint", func(t *testing.T) {
		testHTTPTracesOptions(t, otlpOptions{Scheme: "https", Endpoint: "localhost:3131", BaseURLPath: "/otlp", URLPath: "/otlp/v1/traces", Headers: map[string]string{}}, &tcfg)
	})

	tcfg = TracesConfig{
		CommonEndpoint:   "https://localhost:3131",
		TracesEndpoint:   "http://localhost:3232",
		Instrumentations: []string{instrumentations.InstrumentationALL},
	}
	t.Run("testing with insecure endpoint", func(t *testing.T) {
		testHTTPTracesOptions(t, otlpOptions{Scheme: "http", Endpoint: "localhost:3232", Insecure: true, Headers: map[string]string{}}, &tcfg)
	})

	tcfg = TracesConfig{
		CommonEndpoint:     "https://localhost:3232",
		InsecureSkipVerify: true,
		Instrumentations:   []string{instrumentations.InstrumentationALL},
	}

	t.Run("testing with skip TLS verification", func(t *testing.T) {
		testHTTPTracesOptions(t, otlpOptions{Scheme: "https", Endpoint: "localhost:3232", URLPath: "/v1/traces", SkipTLSVerify: true, Headers: map[string]string{}}, &tcfg)
	})
}

func TestHTTPTracesWithGrafanaOptions(t *testing.T) {
	defer restoreEnvAfterExecution()
	mcfg := TracesConfig{Grafana: &GrafanaOTLP{
		Submit:     []string{submitMetrics, submitTraces},
		CloudZone:  "eu-west-23",
		InstanceID: "12345",
		APIKey:     "affafafaafkd",
	}, Instrumentations: []string{instrumentations.InstrumentationALL}}
	t.Run("testing basic Grafana Cloud options", func(t *testing.T) {
		testHTTPTracesOptions(t, otlpOptions{
			Scheme:      "https",
			Endpoint:    "otlp-gateway-eu-west-23.grafana.net",
			BaseURLPath: "/otlp",
			URLPath:     "/otlp/v1/traces",
			Headers: map[string]string{
				// Basic + output of: echo -n 12345:affafafaafkd | gbase64 -w 0
				"Authorization": "Basic MTIzNDU6YWZmYWZhZmFhZmtk",
			},
		}, &mcfg)
	})
	mcfg.CommonEndpoint = "https://localhost:3939"
	t.Run("Overriding endpoint URL", func(t *testing.T) {
		testHTTPTracesOptions(t, otlpOptions{
			Scheme:   "https",
			Endpoint: "localhost:3939",
			URLPath:  "/v1/traces",
			Headers: map[string]string{
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
	opts, err := getHTTPTracesEndpointOptions(&TracesConfig{CommonEndpoint: "http://foo:3030", Instrumentations: []string{instrumentations.InstrumentationALL}})
	require.NoError(t, err)
	require.NotEmpty(t, opts)

	_, err = getHTTPTracesEndpointOptions(&TracesConfig{CommonEndpoint: "foo:3030", Instrumentations: []string{instrumentations.InstrumentationALL}})
	require.Error(t, err)

	_, err = getHTTPTracesEndpointOptions(&TracesConfig{CommonEndpoint: "foo", Instrumentations: []string{instrumentations.InstrumentationALL}})
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
				TracesEndpoint:   "https://localhost:1234/v1/traces",
				Grafana:          &tc.Grafana,
				Instrumentations: []string{instrumentations.InstrumentationALL},
			})
			require.NoError(t, err)
			assert.Equal(t, tc.ExpectedHeaders, opts.Headers)
		})
	}
}

func TestGRPCTracesEndpointOptions(t *testing.T) {
	defer restoreEnvAfterExecution()()
	t.Run("do not accept URLs without a scheme", func(t *testing.T) {
		_, err := getGRPCTracesEndpointOptions(&TracesConfig{CommonEndpoint: "foo:3939", Instrumentations: []string{instrumentations.InstrumentationALL}})
		assert.Error(t, err)
	})
	tcfg := TracesConfig{
		CommonEndpoint:   "https://localhost:3131",
		TracesEndpoint:   "https://localhost:3232",
		Instrumentations: []string{instrumentations.InstrumentationALL},
	}

	t.Run("testing with two endpoints", func(t *testing.T) {
		testTracesGRPCOptions(t, otlpOptions{Endpoint: "localhost:3232", Headers: map[string]string{}}, &tcfg)
	})

	tcfg = TracesConfig{
		CommonEndpoint:   "https://localhost:3131",
		Instrumentations: []string{instrumentations.InstrumentationALL},
	}

	t.Run("testing with only common endpoint", func(t *testing.T) {
		testTracesGRPCOptions(t, otlpOptions{Endpoint: "localhost:3131", Headers: map[string]string{}}, &tcfg)
	})

	tcfg = TracesConfig{
		CommonEndpoint:   "https://localhost:3131",
		TracesEndpoint:   "http://localhost:3232",
		Instrumentations: []string{instrumentations.InstrumentationALL},
	}
	t.Run("testing with insecure endpoint", func(t *testing.T) {
		testTracesGRPCOptions(t, otlpOptions{Endpoint: "localhost:3232", Insecure: true, Headers: map[string]string{}}, &tcfg)
	})

	tcfg = TracesConfig{
		CommonEndpoint:     "https://localhost:3232",
		InsecureSkipVerify: true,
		Instrumentations:   []string{instrumentations.InstrumentationALL},
	}

	t.Run("testing with skip TLS verification", func(t *testing.T) {
		testTracesGRPCOptions(t, otlpOptions{Endpoint: "localhost:3232", SkipTLSVerify: true, Headers: map[string]string{}}, &tcfg)
	})
}

func TestGRPCTracesEndpointHeaders(t *testing.T) {
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

			opts, err := getGRPCTracesEndpointOptions(&TracesConfig{
				TracesEndpoint:   "https://localhost:1234/v1/traces",
				Grafana:          &tc.Grafana,
				Instrumentations: []string{instrumentations.InstrumentationALL},
			})
			require.NoError(t, err)
			assert.Equal(t, tc.ExpectedHeaders, opts.Headers)
		})
	}
}

func testTracesGRPCOptions(t *testing.T, expected otlpOptions, tcfg *TracesConfig) {
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
				CommonEndpoint:   "http://host:3333",
				TracesEndpoint:   tc.Endpoint,
				Protocol:         tc.ProtoVal,
				TracesProtocol:   tc.TraceProtoVal,
				Instrumentations: []string{instrumentations.InstrumentationALL},
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
			CommonEndpoint:   "http://host:3333",
			Protocol:         "foo",
			TracesProtocol:   "bar",
			Instrumentations: []string{instrumentations.InstrumentationALL},
		})
		require.NoError(t, err)
		assert.Equal(t, "foo-proto", os.Getenv(envProtocol))
		assert.Equal(t, "bar-proto", os.Getenv(envTracesProtocol))
	})
	t.Run("setting only proto env var", func(t *testing.T) {
		defer restoreEnvAfterExecution()()
		require.NoError(t, os.Setenv(envProtocol, "foo-proto"))
		_, err := getHTTPTracesEndpointOptions(&TracesConfig{
			CommonEndpoint:   "http://host:3333",
			Protocol:         "foo",
			Instrumentations: []string{instrumentations.InstrumentationALL},
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
		traces := GenerateTraces(span, "host-id", map[attr.Name]struct{}{}, []attribute.KeyValue{})

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
		traces := GenerateTraces(span, "host-id", map[attr.Name]struct{}{}, []attribute.KeyValue{})

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
		traces := GenerateTraces(span, "host-id", map[attr.Name]struct{}{}, []attribute.KeyValue{})

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
		traces := GenerateTraces(span, "host-id", map[attr.Name]struct{}{}, []attribute.KeyValue{})

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
		traces := GenerateTraces(span, "host-id", map[attr.Name]struct{}{}, []attribute.KeyValue{})

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
		traces := GenerateTraces(span, "host-id", map[attr.Name]struct{}{}, []attribute.KeyValue{})

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
		traces := GenerateTraces(&span, "host-id", map[attr.Name]struct{}{}, []attribute.KeyValue{})

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
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBSystemName), "other_sql")
		ensureTraceAttrNotExists(t, attrs, attribute.Key(attr.DBQueryText))
	})

	t.Run("test SQL trace generation, unknown attribute", func(t *testing.T) {
		span := makeSQLRequestSpan("SELECT password FROM credentials WHERE username=\"bill\"")
		traces := GenerateTraces(&span, "host-id", map[attr.Name]struct{}{"db.operation.name": {}}, []attribute.KeyValue{})

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
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBSystemName), "other_sql")
		ensureTraceAttrNotExists(t, attrs, attribute.Key(attr.DBQueryText))
	})

	t.Run("test SQL trace generation, unknown attribute", func(t *testing.T) {
		span := makeSQLRequestSpan("SELECT password FROM credentials WHERE username=\"bill\"")
		traces := GenerateTraces(&span, "host-id", map[attr.Name]struct{}{attr.DBQueryText: {}}, []attribute.KeyValue{})

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
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBSystemName), "other_sql")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBQueryText), "SELECT password FROM credentials WHERE username=\"bill\"")
	})
	t.Run("test Kafka trace generation", func(t *testing.T) {
		span := request.Span{Type: request.EventTypeKafkaClient, Method: "process", Path: "important-topic", Statement: "test"}
		traces := GenerateTraces(&span, "host-id", map[attr.Name]struct{}{}, []attribute.KeyValue{})

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
	t.Run("test env var resource attributes", func(t *testing.T) {
		defer restoreEnvAfterExecution()()
		require.NoError(t, os.Setenv(envResourceAttrs, "deployment.environment=productions,source.upstream=beyla"))
		span := request.Span{Type: request.EventTypeHTTP, Method: "GET", Route: "/test", Status: 200}
		traces := GenerateTraces(&span, "host-id", map[attr.Name]struct{}{}, ResourceAttrsFromEnv(&span.Service))

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		rs := traces.ResourceSpans().At(0)
		attrs := rs.Resource().Attributes()
		ensureTraceStrAttr(t, attrs, attribute.Key("deployment.environment"), "productions")
		ensureTraceStrAttr(t, attrs, attribute.Key("source.upstream"), "beyla")
	})
}

func TestTraceSampling(t *testing.T) {
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
			Service:      svc.Attrs{},
			TraceID:      RandomTraceID(),
		}
		spans = append(spans, span)
	}

	receiver := makeTracesTestReceiver([]string{"http"})

	t.Run("test sample all", func(t *testing.T) {
		sampler := sdktrace.AlwaysSample()
		attrs := make(map[attr.Name]struct{})

		tr := []ptrace.Traces{}

		exporter := TestExporter{
			collector: func(td ptrace.Traces) {
				tr = append(tr, td)
			},
		}

		receiver.processSpans(exporter, spans, attrs, sampler)
		assert.Equal(t, 10, len(tr))
	})

	t.Run("test sample nothing", func(t *testing.T) {
		sampler := sdktrace.NeverSample()
		attrs := make(map[attr.Name]struct{})

		tr := []ptrace.Traces{}

		exporter := TestExporter{
			collector: func(td ptrace.Traces) {
				tr = append(tr, td)
			},
		}

		receiver.processSpans(exporter, spans, attrs, sampler)
		assert.Equal(t, 0, len(tr))
	})

	t.Run("test sample 1/10th", func(t *testing.T) {
		sampler := sdktrace.TraceIDRatioBased(0.1)
		attrs := make(map[attr.Name]struct{})

		tr := []ptrace.Traces{}

		exporter := TestExporter{
			collector: func(td ptrace.Traces) {
				tr = append(tr, td)
			},
		}

		receiver.processSpans(exporter, spans, attrs, sampler)
		// The result is likely 0,1,2 with 1/10th, but since sampling
		// it's a probabilistic matter, we don't want this test to become
		// flaky as some of them could report even 4-5 samples
		assert.GreaterOrEqual(t, 6, len(tr))
	})
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
			Service:      svc.Attrs{},
			TraceID:      RandomTraceID(),
		}
		spans = append(spans, span)
	}

	t.Run("test with span metrics on", func(t *testing.T) {
		receiver := makeTracesTestReceiverWithSpanMetrics([]string{"http"})

		sampler := sdktrace.AlwaysSample()
		attrs, err := receiver.getConstantAttributes()
		assert.Nil(t, err)

		tr := []ptrace.Traces{}

		exporter := TestExporter{
			collector: func(td ptrace.Traces) {
				tr = append(tr, td)
			},
		}

		receiver.processSpans(exporter, spans, attrs, sampler)
		assert.Equal(t, 10, len(tr))

		for _, ts := range tr {
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
		receiver := makeTracesTestReceiver([]string{"http"})

		sampler := sdktrace.AlwaysSample()
		attrs, err := receiver.getConstantAttributes()
		assert.Nil(t, err)

		tr := []ptrace.Traces{}

		exporter := TestExporter{
			collector: func(td ptrace.Traces) {
				tr = append(tr, td)
			},
		}

		receiver.processSpans(exporter, spans, attrs, sampler)
		assert.Equal(t, 10, len(tr))

		for _, ts := range tr {
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

func TestTracesConfig_Enabled(t *testing.T) {
	assert.True(t, (&TracesConfig{CommonEndpoint: "foo"}).Enabled())
	assert.True(t, (&TracesConfig{TracesEndpoint: "foo"}).Enabled())
	assert.True(t, (&TracesConfig{Grafana: &GrafanaOTLP{Submit: []string{"traces", "metrics"}, InstanceID: "33221"}}).Enabled())
}

func TestTracesConfig_Disabled(t *testing.T) {
	assert.False(t, (&TracesConfig{}).Enabled())
	assert.False(t, (&TracesConfig{Grafana: &GrafanaOTLP{Submit: []string{"metrics"}, InstanceID: "33221"}}).Enabled())
	assert.False(t, (&TracesConfig{Grafana: &GrafanaOTLP{Submit: []string{"traces"}}}).Enabled())
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

func TestTracesInstrumentations(t *testing.T) {
	tests := []InstrTest{
		{
			name:     "all instrumentations",
			instr:    []string{instrumentations.InstrumentationALL},
			expected: []string{"GET /foo", "PUT", "/grpcFoo", "/grpcGoo", "SELECT credentials", "SET", "GET", "important-topic publish", "important-topic process"},
		},
		{
			name:     "http only",
			instr:    []string{instrumentations.InstrumentationHTTP},
			expected: []string{"GET /foo", "PUT"},
		},
		{
			name:     "grpc only",
			instr:    []string{instrumentations.InstrumentationGRPC},
			expected: []string{"/grpcFoo", "/grpcGoo"},
		},
		{
			name:     "redis only",
			instr:    []string{instrumentations.InstrumentationRedis},
			expected: []string{"SET", "GET"},
		},
		{
			name:     "sql only",
			instr:    []string{instrumentations.InstrumentationSQL},
			expected: []string{"SELECT credentials"},
		},
		{
			name:     "kafka only",
			instr:    []string{instrumentations.InstrumentationKafka},
			expected: []string{"important-topic publish", "important-topic process"},
		},
		{
			name:     "none",
			instr:    nil,
			expected: []string{},
		},
		{
			name:     "sql and redis",
			instr:    []string{instrumentations.InstrumentationSQL, instrumentations.InstrumentationRedis},
			expected: []string{"SELECT credentials", "SET", "GET"},
		},
		{
			name:     "kafka and grpc",
			instr:    []string{instrumentations.InstrumentationGRPC, instrumentations.InstrumentationKafka},
			expected: []string{"/grpcFoo", "/grpcGoo", "important-topic publish", "important-topic process"},
		},
	}

	spans := []request.Span{
		{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeHTTP, Method: "GET", Route: "/foo", RequestStart: 100, End: 200},
		{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeHTTPClient, Method: "PUT", Route: "/bar", RequestStart: 150, End: 175},
		{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeGRPC, Path: "/grpcFoo", RequestStart: 100, End: 200},
		{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeGRPCClient, Path: "/grpcGoo", RequestStart: 150, End: 175},
		makeSQLRequestSpan("SELECT password FROM credentials WHERE username=\"bill\""),
		{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeRedisClient, Method: "SET", Path: "redis_db", RequestStart: 150, End: 175},
		{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeRedisServer, Method: "GET", Path: "redis_db", RequestStart: 150, End: 175},
		{Type: request.EventTypeKafkaClient, Method: "process", Path: "important-topic", Statement: "test"},
		{Type: request.EventTypeKafkaServer, Method: "publish", Path: "important-topic", Statement: "test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := makeTracesTestReceiver(tt.instr)
			traces := generateTracesForSpans(t, tr, spans)
			assert.Equal(t, len(traces), len(tt.expected), tt.name)
			for i := 0; i < len(tt.expected); i++ {
				found := false
				for j := 0; j < len(traces); j++ {
					assert.Equal(t, traces[j].ResourceSpans().Len(), 1, tt.name+":"+tt.expected[i])
					if traces[j].ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Name() == tt.expected[i] {
						found = true
						break
					}
				}
				assert.True(t, found, tt.name+":"+tt.expected[i])
			}
		})
	}
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
			Instrumentations:  []string{instrumentations.InstrumentationALL},
		},
		false,
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

func TestTracesAttrReuse(t *testing.T) {
	tests := []struct {
		name string
		span request.Span
		same bool
	}{
		{
			name: "Reuses the trace attributes, with svc.Instance defined",
			span: request.Span{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeHTTP, Method: "GET", Route: "/foo", RequestStart: 100, End: 200},
			same: true,
		},
		{
			name: "No Instance, no caching of trace attributes",
			span: request.Span{Service: svc.Attrs{}, Type: request.EventTypeHTTP, Method: "GET", Route: "/foo", RequestStart: 100, End: 200},
			same: false,
		},
		{
			name: "No Service, no caching of trace attributes",
			span: request.Span{Type: request.EventTypeHTTP, Method: "GET", Route: "/foo", RequestStart: 100, End: 200},
			same: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr1 := traceAppResourceAttrs("123", &tt.span.Service)
			attr2 := traceAppResourceAttrs("123", &tt.span.Service)
			assert.Equal(t, tt.same, &attr1[0] == &attr2[0], tt.name)
		})
	}
}

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

	tr := makeTracesTestReceiver([]string{instrumentations.InstrumentationALL})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			traces := generateTracesForSpans(t, tr, tt.spans)
			assert.Equal(t, tt.filtered, len(traces) == 0, tt.name)
		})
	}
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

func TestHostPeerAttributes(t *testing.T) {
	// Metrics
	tests := []struct {
		name   string
		span   request.Span
		client string
		server string
	}{
		{
			name:   "Same namespaces HTTP",
			span:   request.Span{Type: request.EventTypeHTTP, PeerName: "client", HostName: "server", OtherNamespace: "same", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server",
		},
		{
			name:   "Client in different namespace",
			span:   request.Span{Type: request.EventTypeHTTP, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client.far",
			server: "server",
		},
		{
			name:   "Same namespaces for HTTP client",
			span:   request.Span{Type: request.EventTypeHTTPClient, PeerName: "client", HostName: "server", OtherNamespace: "same", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server",
		},
		{
			name:   "Server in different namespace ",
			span:   request.Span{Type: request.EventTypeHTTPClient, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server.far",
		},
		{
			name:   "Same namespaces GRPC",
			span:   request.Span{Type: request.EventTypeGRPC, PeerName: "client", HostName: "server", OtherNamespace: "same", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server",
		},
		{
			name:   "Client in different namespace GRPC",
			span:   request.Span{Type: request.EventTypeGRPC, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client.far",
			server: "server",
		},
		{
			name:   "Same namespaces for GRPC client",
			span:   request.Span{Type: request.EventTypeGRPCClient, PeerName: "client", HostName: "server", OtherNamespace: "same", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server",
		},
		{
			name:   "Server in different namespace GRPC",
			span:   request.Span{Type: request.EventTypeGRPCClient, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server.far",
		},
		{
			name:   "Same namespaces for SQL client",
			span:   request.Span{Type: request.EventTypeSQLClient, PeerName: "client", HostName: "server", OtherNamespace: "same", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "",
			server: "server",
		},
		{
			name:   "Server in different namespace SQL",
			span:   request.Span{Type: request.EventTypeSQLClient, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "",
			server: "server.far",
		},
		{
			name:   "Same namespaces for Redis client",
			span:   request.Span{Type: request.EventTypeRedisClient, PeerName: "client", HostName: "server", OtherNamespace: "same", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "",
			server: "server",
		},
		{
			name:   "Server in different namespace Redis",
			span:   request.Span{Type: request.EventTypeRedisClient, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "",
			server: "server.far",
		},
		{
			name:   "Client in different namespace Redis",
			span:   request.Span{Type: request.EventTypeRedisServer, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "",
			server: "server",
		},
		{
			name:   "Server in different namespace Kafka",
			span:   request.Span{Type: request.EventTypeKafkaClient, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "",
			server: "server.far",
		},
		{
			name:   "Client in different namespace Kafka",
			span:   request.Span{Type: request.EventTypeKafkaServer, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "",
			server: "server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := traceAttributes(&tt.span, nil)
			if tt.server != "" {
				var found attribute.KeyValue
				for _, a := range attrs {
					if a.Key == attribute.Key(attr.ServerAddr) {
						found = a
						assert.Equal(t, tt.server, a.Value.AsString())
					}
				}
				assert.NotNil(t, found)
			}
			if tt.client != "" {
				var found attribute.KeyValue
				for _, a := range attrs {
					if a.Key == attribute.Key(attr.ClientAddr) {
						found = a
						assert.Equal(t, tt.client, a.Value.AsString())
					}
				}
				assert.NotNil(t, found)
			}
		})
	}
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

func makeTracesTestReceiver(instr []string) *tracesOTELReceiver {
	return makeTracesReceiver(context.Background(),
		TracesConfig{
			CommonEndpoint:    "http://something",
			BatchTimeout:      10 * time.Millisecond,
			ReportersCacheLen: 16,
			Instrumentations:  instr,
		},
		false,
		&global.ContextInfo{},
		attributes.Selection{},
	)
}

func makeTracesTestReceiverWithSpanMetrics(instr []string) *tracesOTELReceiver {
	return makeTracesReceiver(context.Background(),
		TracesConfig{
			CommonEndpoint:    "http://something",
			BatchTimeout:      10 * time.Millisecond,
			ReportersCacheLen: 16,
			Instrumentations:  instr,
		},
		true,
		&global.ContextInfo{},
		attributes.Selection{},
	)
}

func generateTracesForSpans(t *testing.T, tr *tracesOTELReceiver, spans []request.Span) []ptrace.Traces {
	res := []ptrace.Traces{}
	traceAttrs, err := GetUserSelectedAttributes(tr.attributes)
	assert.NoError(t, err)
	for i := range spans {
		span := &spans[i]
		if tr.spanDiscarded(span) {
			continue
		}
		res = append(res, GenerateTraces(span, "host-id", traceAttrs, []attribute.KeyValue{}))
	}

	return res
}

type TestExporter struct {
	collector func(td ptrace.Traces)
}

func (e TestExporter) Start(_ context.Context, _ component.Host) error {
	return nil
}

func (e TestExporter) Shutdown(_ context.Context) error {
	return nil
}

func (e TestExporter) ConsumeTraces(_ context.Context, td ptrace.Traces) error {
	e.collector(td)
	return nil
}

func (e TestExporter) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{}
}

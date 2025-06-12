package otel

import (
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/svc"
	attrobi "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/attribute"

	"github.com/grafana/beyla/v2/pkg/export/attributes"
)

func TestOtlpOptions_AsMetricHTTP(t *testing.T) {
	type testCase struct {
		in  otlpOptions
		len int
	}
	testCases := []testCase{
		{in: otlpOptions{Endpoint: "foo"}, len: 1},
		{in: otlpOptions{Endpoint: "foo", Insecure: true}, len: 2},
		{in: otlpOptions{Endpoint: "foo", URLPath: "/foo"}, len: 2},
		{in: otlpOptions{Endpoint: "foo", SkipTLSVerify: true}, len: 2},
		{in: otlpOptions{Endpoint: "foo", Insecure: true, SkipTLSVerify: true}, len: 3},
		{in: otlpOptions{Endpoint: "foo", URLPath: "/foo", SkipTLSVerify: true}, len: 3},
		{in: otlpOptions{Endpoint: "foo", URLPath: "/foo", Insecure: true, SkipTLSVerify: true}, len: 4},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			assert.Equal(t, tc.len, len(tc.in.AsMetricHTTP()))
		})
	}
}

func TestOtlpOptions_AsMetricGRPC(t *testing.T) {
	type testCase struct {
		in  otlpOptions
		len int
	}
	testCases := []testCase{
		{in: otlpOptions{Endpoint: "foo"}, len: 1},
		{in: otlpOptions{Endpoint: "foo", Insecure: true}, len: 2},
		{in: otlpOptions{Endpoint: "foo", SkipTLSVerify: true}, len: 2},
		{in: otlpOptions{Endpoint: "foo", Insecure: true, SkipTLSVerify: true}, len: 3},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			assert.Equal(t, tc.len, len(tc.in.AsMetricGRPC()))
		})
	}
}

func TestOtlpOptions_AsTraceHTTP(t *testing.T) {
	type testCase struct {
		in  otlpOptions
		len int
	}
	testCases := []testCase{
		{in: otlpOptions{Endpoint: "foo"}, len: 1},
		{in: otlpOptions{Endpoint: "foo", Insecure: true}, len: 2},
		{in: otlpOptions{Endpoint: "foo", URLPath: "/foo"}, len: 2},
		{in: otlpOptions{Endpoint: "foo", SkipTLSVerify: true}, len: 2},
		{in: otlpOptions{Endpoint: "foo", Insecure: true, SkipTLSVerify: true}, len: 3},
		{in: otlpOptions{Endpoint: "foo", URLPath: "/foo", SkipTLSVerify: true}, len: 3},
		{in: otlpOptions{Endpoint: "foo", URLPath: "/foo", Insecure: true, SkipTLSVerify: true}, len: 4},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			assert.Equal(t, tc.len, len(tc.in.AsTraceHTTP()))
		})
	}
}

func TestOtlpOptions_AsTraceGRPC(t *testing.T) {
	type testCase struct {
		in  otlpOptions
		len int
	}
	testCases := []testCase{
		{in: otlpOptions{Endpoint: "foo"}, len: 1},
		{in: otlpOptions{Endpoint: "foo", Insecure: true}, len: 2},
		{in: otlpOptions{Endpoint: "foo", SkipTLSVerify: true}, len: 2},
		{in: otlpOptions{Endpoint: "foo", Insecure: true, SkipTLSVerify: true}, len: 3},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			assert.Equal(t, tc.len, len(tc.in.AsTraceGRPC()))
		})
	}
}

func TestParseOTELEnvVar(t *testing.T) {
	type testCase struct {
		envVar   string
		expected map[string]string
	}

	testCases := []testCase{
		{envVar: "foo=bar", expected: map[string]string{"foo": "bar"}},
		{envVar: "foo=bar,", expected: map[string]string{"foo": "bar"}},
		{envVar: "foo=bar,baz", expected: map[string]string{"foo": "bar"}},
		{envVar: "foo=bar,baz=baz", expected: map[string]string{"foo": "bar", "baz": "baz"}},
		{envVar: "foo=bar,baz=baz ", expected: map[string]string{"foo": "bar", "baz": "baz"}},
		{envVar: "  foo=bar, baz=baz ", expected: map[string]string{"foo": "bar", "baz": "baz"}},
		{envVar: "  foo = bar , baz =baz ", expected: map[string]string{"foo": "bar", "baz": "baz"}},
		{envVar: "  foo = bar , baz =baz= ", expected: map[string]string{"foo": "bar", "baz": "baz="}},
		{envVar: ",a=b , c=d,=", expected: map[string]string{"a": "b", "c": "d"}},
		{envVar: "=", expected: map[string]string{}},
		{envVar: "====", expected: map[string]string{}},
		{envVar: "a====b", expected: map[string]string{"a": "===b"}},
		{envVar: "", expected: map[string]string{}},
	}

	const dummyVar = "foo"

	for _, tc := range testCases {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			actual := map[string]string{}

			apply := func(k string, v string) {
				actual[k] = v
			}

			err := os.Setenv(dummyVar, tc.envVar)

			assert.NoError(t, err)

			parseOTELEnvVar(nil, dummyVar, apply)

			assert.True(t, reflect.DeepEqual(actual, tc.expected))

			err = os.Unsetenv(dummyVar)

			assert.NoError(t, err)
		})
	}
}

func TestParseOTELEnvVarPerService(t *testing.T) {
	type testCase struct {
		envVar   string
		expected map[string]string
	}

	testCases := []testCase{
		{envVar: "foo=bar", expected: map[string]string{"foo": "bar"}},
		{envVar: "foo=bar,", expected: map[string]string{"foo": "bar"}},
		{envVar: "foo=bar,baz", expected: map[string]string{"foo": "bar"}},
		{envVar: "foo=bar,baz=baz", expected: map[string]string{"foo": "bar", "baz": "baz"}},
		{envVar: "foo=bar,baz=baz ", expected: map[string]string{"foo": "bar", "baz": "baz"}},
		{envVar: "  foo=bar, baz=baz ", expected: map[string]string{"foo": "bar", "baz": "baz"}},
		{envVar: "  foo = bar , baz =baz ", expected: map[string]string{"foo": "bar", "baz": "baz"}},
		{envVar: "  foo = bar , baz =baz= ", expected: map[string]string{"foo": "bar", "baz": "baz="}},
		{envVar: ",a=b , c=d,=", expected: map[string]string{"a": "b", "c": "d"}},
		{envVar: "=", expected: map[string]string{}},
		{envVar: "====", expected: map[string]string{}},
		{envVar: "a====b", expected: map[string]string{"a": "===b"}},
		{envVar: "", expected: map[string]string{}},
	}

	const dummyVar = "foo"

	for _, tc := range testCases {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			actual := map[string]string{}

			apply := func(k string, v string) {
				actual[k] = v
			}

			parseOTELEnvVar(&svc.Attrs{EnvVars: map[string]string{dummyVar: tc.envVar}}, dummyVar, apply)

			assert.True(t, reflect.DeepEqual(actual, tc.expected))
		})
	}
}

func TestParseOTELEnvVar_nil(t *testing.T) {
	actual := map[string]string{}

	apply := func(k string, v string) {
		actual[k] = v
	}

	parseOTELEnvVar(nil, "NOT_SET_VAR", apply)

	assert.True(t, reflect.DeepEqual(actual, map[string]string{}))
}

func TestResolveOTLPEndpoint(t *testing.T) {
	grafana1 := GrafanaOTLP{
		CloudZone: "foo",
	}

	const grafanaEndpoint = "https://otlp-gateway-foo.grafana.net/otlp"

	grafana2 := GrafanaOTLP{}

	type expected struct {
		e      string
		common bool
	}

	type testCase struct {
		endpoint string
		common   string
		grafana  *GrafanaOTLP
		expected expected
	}

	testCases := []testCase{
		{endpoint: "e1", common: "c1", grafana: nil, expected: expected{e: "e1", common: false}},
		{endpoint: "e1", common: "", grafana: nil, expected: expected{e: "e1", common: false}},
		{endpoint: "", common: "c1", grafana: nil, expected: expected{e: "c1", common: true}},
		{endpoint: "", common: "", grafana: nil, expected: expected{e: "", common: false}},
		{endpoint: "e1", common: "c1", grafana: &grafana1, expected: expected{e: "e1", common: false}},
		{endpoint: "", common: "c1", grafana: &grafana1, expected: expected{e: "c1", common: true}},
		{endpoint: "", common: "", grafana: &grafana1, expected: expected{e: grafanaEndpoint, common: true}},
		{endpoint: "", common: "", grafana: &grafana2, expected: expected{e: "", common: false}},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			ep, common := ResolveOTLPEndpoint(tc.endpoint, tc.common, tc.grafana)

			assert.Equal(t, ep, tc.expected.e)
			assert.Equal(t, common, tc.expected.common)
		})
	}
}

func TestGetFilteredResourceAttrs(t *testing.T) {
	type testCase struct {
		name            string
		baseAttrs       []attribute.KeyValue
		attrSelector    attributes.Selection
		extraAttrs      []attribute.KeyValue
		prefixPatterns  []string
		expectedAttrs   []string
		unexpectedAttrs []string
	}

	testMetric := attrobi.Name{
		Section: "test.metric",
		Prom:    "test_metric",
		OTEL:    "test.metric",
	}

	testCases := []testCase{
		{
			name: "No filtering configuration",
			baseAttrs: []attribute.KeyValue{
				attribute.String("service.name", "test-service"),
				attribute.String("telemetry.sdk.name", "beyla"),
			},
			attrSelector: attributes.Selection{},
			extraAttrs: []attribute.KeyValue{
				attribute.String("process.command_args", "/bin/test --arg1 --arg2"),
				attribute.String("process.pid", "12345"),
			},
			prefixPatterns: []string{"process."},
			expectedAttrs: []string{
				"service.name",
				"telemetry.sdk.name",
				"process.command_args",
				"process.pid",
			},
			unexpectedAttrs: []string{},
		},
		{
			name: "With filtering configuration excluding process.command_args",
			baseAttrs: []attribute.KeyValue{
				attribute.String("service.name", "test-service"),
				attribute.String("telemetry.sdk.name", "beyla"),
			},
			attrSelector: attributes.Selection{
				testMetric.Section: attributes.InclusionLists{
					Include: []string{"*"},
					Exclude: []string{"process.command_args"},
				},
			},
			extraAttrs: []attribute.KeyValue{
				attribute.String("process.command_args", "/bin/test --arg1 --arg2"),
				attribute.String("process.pid", "12345"),
			},
			prefixPatterns: []string{"test."},
			expectedAttrs: []string{
				"service.name",
				"telemetry.sdk.name",
				"process.pid",
			},
			unexpectedAttrs: []string{
				"process.command_args",
			},
		},
		{
			name: "With filtering configuration using glob patterns",
			baseAttrs: []attribute.KeyValue{
				attribute.String("service.name", "test-service"),
				attribute.String("telemetry.sdk.name", "beyla"),
			},
			attrSelector: attributes.Selection{
				testMetric.Section: attributes.InclusionLists{
					Include: []string{"*"},
					Exclude: []string{"process.*"},
				},
			},
			extraAttrs: []attribute.KeyValue{
				attribute.String("process.command_args", "/bin/test --arg1 --arg2"),
				attribute.String("process.pid", "12345"),
				attribute.String("host.name", "test-host"),
			},
			prefixPatterns: []string{"test."},
			expectedAttrs: []string{
				"service.name",
				"telemetry.sdk.name",
				"host.name",
			},
			unexpectedAttrs: []string{
				"process.command_args",
				"process.pid",
			},
		},
		{
			name: "With different exclusion patterns",
			baseAttrs: []attribute.KeyValue{
				attribute.String("service.name", "test-service"),
				attribute.String("telemetry.sdk.name", "beyla"),
			},
			attrSelector: attributes.Selection{
				testMetric.Section: attributes.InclusionLists{
					Include: []string{"*"},
					Exclude: []string{"process.command_args", "host.*"},
				},
			},
			extraAttrs: []attribute.KeyValue{
				attribute.String("process.command_args", "/bin/test --arg1 --arg2"),
				attribute.String("process.pid", "12345"),
				attribute.String("host.name", "test-host"),
			},
			prefixPatterns: []string{"test."},
			expectedAttrs: []string{
				"service.name",
				"telemetry.sdk.name",
				"process.pid",
			},
			unexpectedAttrs: []string{
				"process.command_args",
				"host.name",
			},
		},
		{
			name: "Testing selector order - specific patterns override general ones",
			baseAttrs: []attribute.KeyValue{
				attribute.String("service.name", "test-service"),
				attribute.String("telemetry.sdk.name", "beyla"),
			},
			attrSelector: attributes.Selection{
				"*": attributes.InclusionLists{
					Include: []string{"*"},
					Exclude: []string{"process.*", "host.*"},
				},
				"test.*": attributes.InclusionLists{
					Exclude: []string{"container.*"},
				},
				"test.metric": attributes.InclusionLists{
					Include: []string{"process.pid", "host.name"},
				},
			},
			extraAttrs: []attribute.KeyValue{
				attribute.String("process.command_args", "/bin/test --arg1 --arg2"),
				attribute.String("process.pid", "12345"),
				attribute.String("host.name", "test-host"),
				attribute.String("container.id", "container123"),
			},
			prefixPatterns: []string{"test."},
			expectedAttrs: []string{
				"service.name",
				"telemetry.sdk.name",
				"process.pid",
				"host.name",
			},
			unexpectedAttrs: []string{
				"process.command_args",
				"container.id",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := getFilteredAttributesByPrefix(tc.baseAttrs, tc.attrSelector, tc.extraAttrs, tc.prefixPatterns)

			attrMap := make(map[string]attribute.Value)
			for _, attr := range result {
				attrMap[string(attr.Key)] = attr.Value
			}

			for _, attrName := range tc.expectedAttrs {
				_, ok := attrMap[attrName]
				assert.True(t, ok, "Expected attribute %s not found in result", attrName)
			}

			for _, attrName := range tc.unexpectedAttrs {
				_, ok := attrMap[attrName]
				assert.False(t, ok, "Unexpected attribute %s found in result", attrName)
			}
		})
	}
}

package otel

import (
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
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

			parseOTELEnvVar(dummyVar, apply)

			assert.True(t, reflect.DeepEqual(actual, tc.expected))

			err = os.Unsetenv(dummyVar)

			assert.NoError(t, err)
		})
	}
}

func TestParseOTELEnvVar_nil(t *testing.T) {
	actual := map[string]string{}

	apply := func(k string, v string) {
		actual[k] = v
	}

	parseOTELEnvVar("NOT_SET_VAR", apply)

	assert.True(t, reflect.DeepEqual(actual, map[string]string{}))
}

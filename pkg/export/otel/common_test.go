package otel

import (
	"fmt"
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

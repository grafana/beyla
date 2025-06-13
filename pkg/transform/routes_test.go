package transform

import (
	"context"
	"testing"
	"time"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/app/request"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/testutil"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	internalrequest "github.com/grafana/beyla/v2/pkg/internal/request"
)

const testTimeout = 5 * time.Second

func TestUnmatchedWildcard(t *testing.T) {
	for _, tc := range []UnmatchType{"", UnmatchWildcard, "invalid_value"} {
		t.Run(string(tc), func(t *testing.T) {
			input := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
			output := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
			router, err := RoutesProvider(&RoutesConfig{Unmatch: tc, Patterns: []string{"/user/:id"}},
				input, output)(context.Background())
			require.NoError(t, err)
			out := output.Subscribe()
			defer input.Close()
			go router(context.Background())
			input.Send([]request.Span{{Path: "/user/1234"}})
			assert.Equal(t, []request.Span{{
				Path:  "/user/1234",
				Route: "/user/:id",
			}}, testutil.ReadChannel(t, out, testTimeout))
			input.Send([]request.Span{{Path: "/some/path"}})
			assert.Equal(t, []request.Span{{
				Path:  "/some/path",
				Route: "/**",
			}}, testutil.ReadChannel(t, out, testTimeout))
		})
	}
}

func TestUnmatchedPath(t *testing.T) {
	input := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	output := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	router, err := RoutesProvider(&RoutesConfig{Unmatch: UnmatchPath, Patterns: []string{"/user/:id"}},
		input, output)(context.Background())
	require.NoError(t, err)
	out := output.Subscribe()
	defer input.Close()
	go router(context.Background())
	input.Send([]request.Span{{Path: "/user/1234"}})
	assert.Equal(t, []request.Span{{
		Path:  "/user/1234",
		Route: "/user/:id",
	}}, testutil.ReadChannel(t, out, testTimeout))
	input.Send([]request.Span{{Path: "/some/path"}})
	assert.Equal(t, []request.Span{{
		Path:  "/some/path",
		Route: "/some/path",
	}}, testutil.ReadChannel(t, out, testTimeout))
}

func TestUnmatchedEmpty(t *testing.T) {
	input := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	output := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	router, err := RoutesProvider(&RoutesConfig{Unmatch: UnmatchUnset, Patterns: []string{"/user/:id"}},
		input, output)(context.Background())
	require.NoError(t, err)
	out := output.Subscribe()
	defer input.Close()
	go router(context.Background())
	input.Send([]request.Span{{Path: "/user/1234"}})
	assert.Equal(t, []request.Span{{
		Path:  "/user/1234",
		Route: "/user/:id",
	}}, testutil.ReadChannel(t, out, testTimeout))
	input.Send([]request.Span{{Path: "/some/path"}})
	assert.Equal(t, []request.Span{{
		Path: "/some/path",
	}}, testutil.ReadChannel(t, out, testTimeout))
}

func TestUnmatchedAuto(t *testing.T) {
	for _, tc := range []UnmatchType{UnmatchHeuristic} {
		t.Run(string(tc), func(t *testing.T) {
			input := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
			output := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
			router, err := RoutesProvider(&RoutesConfig{Unmatch: tc, Patterns: []string{"/user/:id"}, WildcardChar: "*"},
				input, output)(context.Background())
			require.NoError(t, err)
			out := output.Subscribe()
			defer input.Close()
			go router(context.Background())
			input.Send([]request.Span{{Path: "/user/1234"}})
			assert.Equal(t, []request.Span{{
				Path:  "/user/1234",
				Route: "/user/:id",
			}}, testutil.ReadChannel(t, out, testTimeout))
			input.Send([]request.Span{{Path: "/some/path", Type: request.EventTypeHTTP}})
			assert.Equal(t, []request.Span{{
				Path:  "/some/path",
				Route: "/some/path",
				Type:  request.EventTypeHTTP,
			}}, testutil.ReadChannel(t, out, testTimeout))
			input.Send([]request.Span{{Path: "/customer/1/job/2", Type: request.EventTypeHTTP}})
			assert.Equal(t, []request.Span{{
				Path:  "/customer/1/job/2",
				Route: "/customer/*/job/*",
				Type:  request.EventTypeHTTP,
			}}, testutil.ReadChannel(t, out, testTimeout))
			input.Send([]request.Span{{Path: "/customer/lfdsjd/job/erwejre", Type: request.EventTypeHTTPClient}})
			assert.Equal(t, []request.Span{{
				Path:  "/customer/lfdsjd/job/erwejre",
				Route: "/customer/*/job/*",
				Type:  request.EventTypeHTTPClient,
			}}, testutil.ReadChannel(t, out, testTimeout))
		})
	}
}

func TestIgnoreRoutes(t *testing.T) {
	input := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	output := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	router, err := RoutesProvider(&RoutesConfig{
		Unmatch: UnmatchPath, Patterns: []string{"/user/:id", "/v1/metrics"},
		IgnorePatterns: []string{"/v1/metrics/*", "/v1/traces/*", "/exact"}},
		input, output)(context.Background())
	require.NoError(t, err)
	out := output.Subscribe()
	defer input.Close()
	go router(context.Background())
	input.Send([]request.Span{{Path: "/user/1234"}})
	input.Send([]request.Span{{Path: "/v1/metrics"}}) // this is in routes and ignore, ignore takes precedence
	input.Send([]request.Span{{Path: "/v1/traces/1234/test"}})
	input.Send([]request.Span{{Path: "/v1/metrics/1234/test"}}) // this is in routes and ignore, ignore takes precedence
	input.Send([]request.Span{{Path: "/v1/traces"}})
	input.Send([]request.Span{{Path: "/exact"}})
	input.Send([]request.Span{{Path: "/some/path"}})
	assert.Equal(t, []request.Span{{
		Path:  "/user/1234",
		Route: "/user/:id",
	}}, filterIgnored(func() []request.Span { return testutil.ReadChannel(t, out, testTimeout) }))
	assert.Equal(t, []request.Span{{
		Path:  "/some/path",
		Route: "/some/path",
	}}, filterIgnored(func() []request.Span { return testutil.ReadChannel(t, out, testTimeout) }))
}

func TestIgnoreMode(t *testing.T) {
	s := request.Span{Path: "/user/1234"}
	setSpanIgnoreMode(IgnoreTraces, &s)
	assert.True(t, internalrequest.IgnoreTraces(&s))
	setSpanIgnoreMode(IgnoreMetrics, &s)
	assert.True(t, internalrequest.IgnoreMetrics(&s))
}

func BenchmarkRoutesProvider_Wildcard(b *testing.B) {
	benchProvider(b, UnmatchWildcard)
}

func BenchmarkRoutesProvider_Heuristic(b *testing.B) {
	benchProvider(b, UnmatchHeuristic)
}

func benchProvider(b *testing.B, unmatch UnmatchType) {
	input := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	output := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	router, err := RoutesProvider(&RoutesConfig{Unmatch: unmatch, Patterns: []string{
		"/users/{id}",
		"/users/{id}/product/{pid}",
	}}, input, output)(context.Background())

	if err != nil {
		b.Fatal(err)
	}
	inCh, outCh := make(chan []request.Span, 10), make(chan []request.Span, 10)
	// 40% of unmatched routes
	benchmarkInput := []request.Span{
		{Type: request.EventTypeHTTP, Path: "/users/123"},
		{Type: request.EventTypeHTTP, Path: "/users/123/product/456"},
		{Type: request.EventTypeHTTP, Path: "/users"},
		{Type: request.EventTypeHTTP, Path: "/products/34322"},
		{Type: request.EventTypeHTTP, Path: "/users/123/delete"},
	}
	go router(context.Background())
	for i := 0; i < b.N; i++ {
		inCh <- benchmarkInput
		<-outCh
	}
}

func filterIgnored(reader func() []request.Span) []request.Span {
	for {
		input := reader()
		output := make([]request.Span, 0, len(input))
		for i := range input {
			s := &input[i]

			if internalrequest.IgnoreMetrics(s) {
				continue
			}

			if internalrequest.IgnoreTraces(s) {
				continue
			}

			output = append(output, *s)
		}

		if len(output) > 0 {
			return output
		}
	}
}

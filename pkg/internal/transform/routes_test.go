package transform

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/testutil"
)

const testTimeout = 5 * time.Second

func TestUnmatchedWildcard(t *testing.T) {
	for _, tc := range []UnmatchType{"", UnmatchWildcard, "invalid_value"} {
		t.Run(string(tc), func(t *testing.T) {
			router, err := RoutesProvider(&RoutesConfig{Unmatch: tc, Patterns: []string{"/user/:id"}})
			require.NoError(t, err)
			in, out := make(chan []request.Span, 10), make(chan []request.Span, 10)
			defer close(in)
			go router(in, out)
			in <- []request.Span{{Path: "/user/1234"}}
			assert.Equal(t, []request.Span{{
				Path:  "/user/1234",
				Route: "/user/:id",
			}}, testutil.ReadChannel(t, out, testTimeout))
			in <- []request.Span{{Path: "/some/path"}}
			assert.Equal(t, []request.Span{{
				Path:  "/some/path",
				Route: "/**",
			}}, testutil.ReadChannel(t, out, testTimeout))
		})
	}
}

func TestUnmatchedPath(t *testing.T) {
	router, err := RoutesProvider(&RoutesConfig{Unmatch: UnmatchPath, Patterns: []string{"/user/:id"}})
	require.NoError(t, err)
	in, out := make(chan []request.Span, 10), make(chan []request.Span, 10)
	defer close(in)
	go router(in, out)
	in <- []request.Span{{Path: "/user/1234"}}
	assert.Equal(t, []request.Span{{
		Path:  "/user/1234",
		Route: "/user/:id",
	}}, testutil.ReadChannel(t, out, testTimeout))
	in <- []request.Span{{Path: "/some/path"}}
	assert.Equal(t, []request.Span{{
		Path:  "/some/path",
		Route: "/some/path",
	}}, testutil.ReadChannel(t, out, testTimeout))
}

func TestUnmatchedEmpty(t *testing.T) {
	router, err := RoutesProvider(&RoutesConfig{Unmatch: UnmatchUnset, Patterns: []string{"/user/:id"}})
	require.NoError(t, err)
	in, out := make(chan []request.Span, 10), make(chan []request.Span, 10)
	defer close(in)
	go router(in, out)
	in <- []request.Span{{Path: "/user/1234"}}
	assert.Equal(t, []request.Span{{
		Path:  "/user/1234",
		Route: "/user/:id",
	}}, testutil.ReadChannel(t, out, testTimeout))
	in <- []request.Span{{Path: "/some/path"}}
	assert.Equal(t, []request.Span{{
		Path: "/some/path",
	}}, testutil.ReadChannel(t, out, testTimeout))
}

func TestUnmatchedAuto(t *testing.T) {
	for _, tc := range []UnmatchType{UnmatchHeuristic} {
		t.Run(string(tc), func(t *testing.T) {
			router, err := RoutesProvider(&RoutesConfig{Unmatch: tc, Patterns: []string{"/user/:id"}})
			require.NoError(t, err)
			in, out := make(chan []request.Span, 10), make(chan []request.Span, 10)
			defer close(in)
			go router(in, out)
			in <- []request.Span{{Path: "/user/1234"}}
			assert.Equal(t, []request.Span{{
				Path:  "/user/1234",
				Route: "/user/:id",
			}}, testutil.ReadChannel(t, out, testTimeout))
			in <- []request.Span{{Path: "/some/path", Type: request.EventTypeHTTP}}
			assert.Equal(t, []request.Span{{
				Path:  "/some/path",
				Route: "/some/path",
				Type:  request.EventTypeHTTP,
			}}, testutil.ReadChannel(t, out, testTimeout))
			in <- []request.Span{{Path: "/customer/1/job/2", Type: request.EventTypeHTTP}}
			assert.Equal(t, []request.Span{{
				Path:  "/customer/1/job/2",
				Route: "/customer/*/job/*",
				Type:  request.EventTypeHTTP,
			}}, testutil.ReadChannel(t, out, testTimeout))
			in <- []request.Span{{Path: "/customer/lfdsjd/job/erwejre", Type: request.EventTypeHTTPClient}}
			assert.Equal(t, []request.Span{{
				Path:  "/customer/lfdsjd/job/erwejre",
				Route: "/customer/*/job/*",
				Type:  request.EventTypeHTTPClient,
			}}, testutil.ReadChannel(t, out, testTimeout))
		})
	}
}

func TestIgnoreRoutes(t *testing.T) {
	router, err := RoutesProvider(&RoutesConfig{Unmatch: UnmatchPath, Patterns: []string{"/user/:id", "/v1/metrics"}, IgnorePatterns: []string{"/v1/metrics/*", "/v1/traces/*", "/exact"}})
	require.NoError(t, err)
	in, out := make(chan []request.Span, 10), make(chan []request.Span, 10)
	defer close(in)
	go router(in, out)
	in <- []request.Span{{Path: "/user/1234"}}
	in <- []request.Span{{Path: "/v1/metrics"}} // this is in routes and ignore, ignore takes precedence
	in <- []request.Span{{Path: "/v1/traces/1234/test"}}
	in <- []request.Span{{Path: "/v1/metrics/1234/test"}} // this is in routes and ignore, ignore takes precedence
	in <- []request.Span{{Path: "/v1/traces"}}
	in <- []request.Span{{Path: "/exact"}}
	in <- []request.Span{{Path: "/some/path"}}
	assert.Equal(t, []request.Span{{
		Path:  "/user/1234",
		Route: "/user/:id",
	}}, testutil.ReadChannel(t, out, testTimeout))
	assert.Equal(t, []request.Span{{
		Path:  "/some/path",
		Route: "/some/path",
	}}, testutil.ReadChannel(t, out, testTimeout))
}

func TestIgnoreMode(t *testing.T) {
	s := request.Span{Path: "/user/1234"}
	setSpanIgnoreMode(IgnoreTraces, &s)
	assert.Equal(t, request.IgnoreTraces, s.IgnoreSpan)
	setSpanIgnoreMode(IgnoreMetrics, &s)
	assert.Equal(t, request.IgnoreMetrics, s.IgnoreSpan)
}

func BenchmarkRoutesProvider_Wildcard(b *testing.B) {
	benchProvider(b, UnmatchWildcard)
}

func BenchmarkRoutesProvider_Heuristic(b *testing.B) {
	benchProvider(b, UnmatchHeuristic)
}

func benchProvider(b *testing.B, unmatch UnmatchType) {
	router, err := RoutesProvider(&RoutesConfig{Unmatch: unmatch, Patterns: []string{
		"/users/{id}",
		"/users/{id}/product/{pid}",
	}})
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
	go router(inCh, outCh)
	for i := 0; i < b.N; i++ {
		inCh <- benchmarkInput
		<-outCh
	}
}

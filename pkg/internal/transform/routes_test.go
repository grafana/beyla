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

package transform

import (
	"testing"
	"time"

	"github.com/grafana/ebpf-autoinstrument/pkg/testutil"

	"github.com/stretchr/testify/assert"
)

const testTimeout = 5 * time.Second

func TestUnmatchedWildcard(t *testing.T) {
	for _, tc := range []UnmatchType{"", UnmatchWildcard, "invalid_value"} {
		t.Run(string(tc), func(t *testing.T) {
			router := RoutesProvider(&RoutesConfig{Unmatch: tc, Patterns: []string{"/user/:id"}})
			in, out := make(chan []HTTPRequestSpan, 10), make(chan []HTTPRequestSpan, 10)
			defer close(in)
			go router(in, out)
			in <- []HTTPRequestSpan{{Path: "/user/1234"}}
			assert.Equal(t, []HTTPRequestSpan{{
				Path:  "/user/1234",
				Route: "/user/:id",
			}}, testutil.ReadChannel(t, out, testTimeout))
			in <- []HTTPRequestSpan{{Path: "/some/path"}}
			assert.Equal(t, []HTTPRequestSpan{{
				Path:  "/some/path",
				Route: "*",
			}}, testutil.ReadChannel(t, out, testTimeout))
		})
	}
}

func TestUnmatchedPath(t *testing.T) {
	router := RoutesProvider(&RoutesConfig{Unmatch: UnmatchPath, Patterns: []string{"/user/:id"}})
	in, out := make(chan []HTTPRequestSpan, 10), make(chan []HTTPRequestSpan, 10)
	defer close(in)
	go router(in, out)
	in <- []HTTPRequestSpan{{Path: "/user/1234"}}
	assert.Equal(t, []HTTPRequestSpan{{
		Path:  "/user/1234",
		Route: "/user/:id",
	}}, testutil.ReadChannel(t, out, testTimeout))
	in <- []HTTPRequestSpan{{Path: "/some/path"}}
	assert.Equal(t, []HTTPRequestSpan{{
		Path:  "/some/path",
		Route: "/some/path",
	}}, testutil.ReadChannel(t, out, testTimeout))
}

func TestUnmatchedEmpty(t *testing.T) {
	router := RoutesProvider(&RoutesConfig{Unmatch: UnmatchUnset, Patterns: []string{"/user/:id"}})
	in, out := make(chan []HTTPRequestSpan, 10), make(chan []HTTPRequestSpan, 10)
	defer close(in)
	go router(in, out)
	in <- []HTTPRequestSpan{{Path: "/user/1234"}}
	assert.Equal(t, []HTTPRequestSpan{{
		Path:  "/user/1234",
		Route: "/user/:id",
	}}, testutil.ReadChannel(t, out, testTimeout))
	in <- []HTTPRequestSpan{{Path: "/some/path"}}
	assert.Equal(t, []HTTPRequestSpan{{
		Path: "/some/path",
	}}, testutil.ReadChannel(t, out, testTimeout))
}

package transform

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const testTimeout = 5 * time.Second

func readChan(t *testing.T, ch <-chan []HTTPRequestSpan) []HTTPRequestSpan {
	t.Helper()
	select {
	case <-time.After(testTimeout):
		t.Fatal("timeout while waiting for data on channel")
		return nil
	case s := <-ch:
		return s
	}
}

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
			}}, readChan(t, out))
			in <- []HTTPRequestSpan{{Path: "/some/path"}}
			assert.Equal(t, []HTTPRequestSpan{{
				Path:  "/some/path",
				Route: "*",
			}}, readChan(t, out))
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
	}}, readChan(t, out))
	in <- []HTTPRequestSpan{{Path: "/some/path"}}
	assert.Equal(t, []HTTPRequestSpan{{
		Path:  "/some/path",
		Route: "/some/path",
	}}, readChan(t, out))
}

func TestUnmatchedEmpty(t *testing.T) {
	router := RoutesProvider(&RoutesConfig{Unmatch: UnmatchEmpty, Patterns: []string{"/user/:id"}})
	in, out := make(chan []HTTPRequestSpan, 10), make(chan []HTTPRequestSpan, 10)
	defer close(in)
	go router(in, out)
	in <- []HTTPRequestSpan{{Path: "/user/1234"}}
	assert.Equal(t, []HTTPRequestSpan{{
		Path:  "/user/1234",
		Route: "/user/:id",
	}}, readChan(t, out))
	in <- []HTTPRequestSpan{{Path: "/some/path"}}
	assert.Equal(t, []HTTPRequestSpan{{
		Path: "/some/path",
	}}, readChan(t, out))
}

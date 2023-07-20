package gorillamid

import "net/http"

// Interface is the shared contract for all middleware, and allows middlewares
// to wrap handlers.
type Interface interface {
	Wrap(http.Handler) http.Handler
}

// Func is to Interface as http.HandlerFunc is to http.Handler
type Func func(http.Handler) http.Handler

// Wrap implements Interface
func (m Func) Wrap(next http.Handler) http.Handler {
	return m(next)
}

// Merge produces a middleware that applies multiple middlewares in turn;
// ie Merge(f,g,h).Wrap(handler) == f.Wrap(g.Wrap(h.Wrap(handler)))
func Merge(middlewares ...Interface) Interface {
	return Func(func(next http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			next = middlewares[i].Wrap(next)
		}
		return next
	})
}

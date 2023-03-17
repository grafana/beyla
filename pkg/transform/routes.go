// Package transform provides some intermediate nodes that might filter/process/transform the events
package transform

import (
	"github.com/grafana/http-autoinstrument/pkg/transform/route"
	"github.com/mariomac/pipes/pkg/node"
)

// RoutesConfig allows grouping URLs sharing a given pattern.
type RoutesConfig []string

type RouterPattern string

func (rc RoutesConfig) Enabled() bool {
	return len(rc) > 0
}

func RoutesProvider(rc RoutesConfig) node.MiddleFunc[HTTPRequestSpan, HTTPRequestSpan] {
	matcher := route.NewMatcher(rc)
	return func(in <-chan HTTPRequestSpan, out chan<- HTTPRequestSpan) {
		for s := range in {
			s.Route = matcher.Find(s.Path)
			out <- s
		}
	}
}

// Package debug provides some export nodes that are aimed basically at debugging/testing
package debug

import (
	"fmt"

	"github.com/mariomac/pipes/pkg/node"

	"github.com/grafana/beyla/pkg/internal/request"
)

type PrintEnabled bool

func (p PrintEnabled) Enabled() bool {
	return bool(p)
}

func PrinterNode(_ PrintEnabled) (node.TerminalFunc[[]request.Span], error) {
	return func(input <-chan []request.Span) {
		for spans := range input {
			for i := range spans {
				t := spans[i].Timings()
				fmt.Printf("%s (%s[%s]) %v %s %s [%s]->[%s:%d] size:%dB svc=[%s] traceparent=[%s]\n",
					t.Start.Format("2006-01-02 15:04:05.12345"),
					t.End.Sub(t.RequestStart),
					t.End.Sub(t.Start),
					spans[i].Status,
					spans[i].Method,
					spans[i].Path,
					spans[i].Peer,
					spans[i].Host,
					spans[i].HostPort,
					spans[i].ContentLength,
					spans[i].ServiceID,
					spans[i].Traceparent,
				)
			}
		}
	}, nil
}

type NoopEnabled bool

func (n NoopEnabled) Enabled() bool {
	return bool(n)
}
func NoopNode(_ NoopEnabled) (node.TerminalFunc[[]request.Span], error) {
	counter := 0
	return func(spans <-chan []request.Span) {
		for range spans {
			counter += len(spans)
		}
		fmt.Printf("Processed %d requests\n", counter)
	}, nil
}

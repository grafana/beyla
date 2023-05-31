// Package debug provides some export nodes that are aimed basically at debugging/testing
package debug

import (
	"context"
	"fmt"

	"github.com/grafana/ebpf-autoinstrument/pkg/transform"
	"github.com/mariomac/pipes/pkg/node"
)

type PrintEnabled bool

func (p PrintEnabled) Enabled() bool {
	return bool(p)
}

func PrinterNode(_ context.Context, _ PrintEnabled) (node.TerminalFunc[[]transform.HTTPRequestSpan], error) {
	return func(input <-chan []transform.HTTPRequestSpan) {
		for spans := range input {
			for i := range spans {
				t := spans[i].Timings()
				fmt.Printf("%s (%s[%s]) %v %s %s [%s]->[%s:%d] size:%dB comm=[%s]\n",
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
					spans[i].ServiceName,
				)
			}
		}
	}, nil
}

type NoopEnabled bool

func (n NoopEnabled) Enabled() bool {
	return bool(n)
}
func NoopNode(_ context.Context, _ NoopEnabled) (node.TerminalFunc[[]transform.HTTPRequestSpan], error) {
	counter := 0
	return func(spans <-chan []transform.HTTPRequestSpan) {
		for range spans {
			counter += len(spans)
		}
		fmt.Printf("Processed %d requests\n", counter)
	}, nil
}

// Package debug provides some export nodes that are aimed basically at debugging/testing
package debug

import (
	"fmt"

	"github.com/grafana/ebpf-autoinstrument/pkg/transform"
	"github.com/mariomac/pipes/pkg/node"
)

type PrintEnabled bool

func (p PrintEnabled) Enabled() bool {
	return bool(p)
}

func PrinterNode(_ PrintEnabled) node.TerminalFunc[[]transform.HTTPRequestSpan] {
	return func(input <-chan []transform.HTTPRequestSpan) {
		for spans := range input {
			for i := range spans {
				fmt.Printf("%s (%s[%s]) %v %s %s [%s]->[%s:%d] size:%dB\n",
					spans[i].Start.Format("2006-01-02 15:04:05.12345"),
					spans[i].End.Sub(spans[i].RequestStart),
					spans[i].End.Sub(spans[i].Start),
					spans[i].Status,
					spans[i].Method,
					spans[i].Path,
					spans[i].Peer,
					spans[i].Host,
					spans[i].HostPort,
					spans[i].ContentLength,
				)
			}
		}
	}
}

type NoopEnabled bool

func (n NoopEnabled) Enabled() bool {
	return bool(n)
}
func NoopNode(_ NoopEnabled) node.TerminalFunc[[]transform.HTTPRequestSpan] {
	counter := 0
	return func(spans <-chan []transform.HTTPRequestSpan) {
		for range spans {
			counter += len(spans)
		}
		fmt.Printf("Processed %d requests\n", counter)
	}
}

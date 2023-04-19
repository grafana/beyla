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

func PrinterNode(_ PrintEnabled) node.TerminalFunc[transform.HTTPRequestSpan] {
	return func(spans <-chan transform.HTTPRequestSpan) {
		for span := range spans {
			fmt.Printf("%s (%s[%s]) %v %s %s [%s]->[%s:%d] size:%dB\n",
				span.Start.Format("2006-01-02 15:04:05.12345"),
				span.End.Sub(span.RequestStart),
				span.End.Sub(span.Start),
				span.Status,
				span.Method,
				span.Path,
				span.Peer,
				span.Host,
				span.HostPort,
				span.ContentLength,
			)
		}
	}
}

type NoopEnabled bool

func (n NoopEnabled) Enabled() bool {
	return bool(n)
}
func NoopNode(_ NoopEnabled) node.TerminalFunc[transform.HTTPRequestSpan] {
	counter := 0
	return func(spans <-chan transform.HTTPRequestSpan) {
		for range spans {
			counter++
		}
		fmt.Printf("Processed %d requests\n", counter)
	}
}

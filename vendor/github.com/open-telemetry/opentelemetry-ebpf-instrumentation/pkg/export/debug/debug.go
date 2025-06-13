// Package debug provides some export nodes that are aimed basically at debugging/testing
package debug

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/app/request"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/swarm"
)

type TracePrinter string

const (
	TracePrinterDisabled   = TracePrinter("disabled")
	TracePrinterCounter    = TracePrinter("counter")
	TracePrinterText       = TracePrinter("text")
	TracePrinterJSON       = TracePrinter("json")
	TracePrinterJSONIndent = TracePrinter("json_indent")
)

func mlog() *slog.Logger {
	return slog.With("component", "debug.TracePrinter")
}

func (t TracePrinter) Valid() bool {
	switch t {
	case TracePrinterDisabled, TracePrinterText, TracePrinterJSON, TracePrinterJSONIndent, TracePrinterCounter:
		return true
	}

	return false
}

func (t TracePrinter) Enabled() bool {
	return t.Valid() && t != TracePrinterDisabled
}

func resolvePrinterFunc(p TracePrinter, input *msg.Queue[[]request.Span]) swarm.RunFunc {
	const (
		jsonIndent   = true
		jsonNoIndent = false
	)

	switch p {
	case TracePrinterText:
		return textPrinter(input)
	case TracePrinterJSON:
		return jsonPrinter(input, jsonNoIndent)
	case TracePrinterJSONIndent:
		return jsonPrinter(input, jsonIndent)
	case TracePrinterCounter:
		return counterPrinter(input)
	}

	// do nothing
	return func(_ context.Context) {}
}

func PrinterNode(p TracePrinter, input *msg.Queue[[]request.Span]) swarm.InstanceFunc {
	return swarm.DirectInstance(resolvePrinterFunc(p, input))
}

func textPrinter(in *msg.Queue[[]request.Span]) swarm.RunFunc {
	input := in.Subscribe()
	return func(_ context.Context) {
		for spans := range input {
			for i := range spans {
				t := spans[i].Timings()

				pn := ""
				hn := ""

				if spans[i].IsClientSpan() {
					if spans[i].Service.UID.Namespace != "" {
						pn = "." + spans[i].Service.UID.Namespace
					}
					if spans[i].OtherNamespace != "" {
						hn = "." + spans[i].OtherNamespace
					}
				} else {
					if spans[i].OtherNamespace != "" {
						pn = "." + spans[i].OtherNamespace
					}
					if spans[i].Service.UID.Namespace != "" {
						hn = "." + spans[i].Service.UID.Namespace
					}
				}

				fmt.Printf("%s (%s[%s]) %s %v %s %s [%s:%d]->[%s:%d] contentLen:%dB responseLen:%dB svc=[%s %s] traceparent=[%s]\n",
					t.Start.Format("2006-01-02 15:04:05.12345"),
					t.End.Sub(t.RequestStart),
					t.End.Sub(t.Start),
					spans[i].Type,
					spans[i].Status,
					spans[i].Method,
					spans[i].Path,
					spans[i].Peer+" as "+request.SpanPeer(&spans[i])+pn,
					spans[i].PeerPort,
					spans[i].Host+" as "+request.SpanHost(&spans[i])+hn,
					spans[i].HostPort,
					spans[i].ContentLength,
					spans[i].ResponseLength,
					&spans[i].Service,
					spans[i].Service.SDKLanguage.String(),
					traceparent(&spans[i]),
				)
			}
		}
	}
}

func serializeSpansJSON(spans []request.Span, indent bool) ([]byte, error) {
	if indent {
		return json.MarshalIndent(spans, "", " ")
	}

	return json.Marshal(spans)
}

func jsonPrinter(in *msg.Queue[[]request.Span], indent bool) swarm.RunFunc {
	input := in.Subscribe()
	return func(_ context.Context) {
		for spans := range input {
			data, err := serializeSpansJSON(spans, indent)
			if err != nil {
				mlog().Error("Error serializing span to json", "error", err)
				continue
			}

			fmt.Printf("%s\n", data)
		}
	}
}

func traceparent(span *request.Span) string {
	if !span.TraceID.IsValid() {
		return ""
	}
	return fmt.Sprintf("00-%s-%s[%s]-%02x", span.TraceID.String(), span.SpanID.String(), span.ParentSpanID.String(), span.TraceFlags)
}

func counterPrinter(in *msg.Queue[[]request.Span]) swarm.RunFunc {
	input := in.Subscribe()
	counter := 0
	return func(_ context.Context) {
		for spans := range input {
			counter += len(spans)
		}

		fmt.Printf("Processed %d requests\n", counter)
	}
}

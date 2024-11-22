// Package debug provides some export nodes that are aimed basically at debugging/testing
package debug

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/mariomac/pipes/pipe"
	"go.opentelemetry.io/otel/trace"

	"github.com/grafana/beyla/pkg/internal/request"
)

// TODO deprecated (REMOVE) - use TracePrinter instead
type PrintEnabled bool

func (p PrintEnabled) Enabled() bool {
	return bool(p)
}

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

func resolvePrinterFunc(p TracePrinter) pipe.FinalFunc[[]request.Span] {
	const (
		jsonIndent   = true
		jsonNoIndent = false
	)

	switch p {
	case TracePrinterText:
		return textPrinter
	case TracePrinterJSON:
		return func(input <-chan []request.Span) { jsonPrinter(input, jsonNoIndent) }
	case TracePrinterJSONIndent:
		return func(input <-chan []request.Span) { jsonPrinter(input, jsonIndent) }
	case TracePrinterCounter:
		return makeCounterPrinter()
	}

	return pipe.IgnoreFinal[[]request.Span]()
}

func PrinterNode(p TracePrinter) pipe.FinalProvider[[]request.Span] {
	printerFunc := resolvePrinterFunc(p)

	return func() (pipe.FinalFunc[[]request.Span], error) {
		return printerFunc, nil
	}
}

func textPrinter(input <-chan []request.Span) {
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

			fmt.Printf("%s (%s[%s]) %s %v %s %s [%s:%d]->[%s:%d] size:%dB svc=[%s %s] traceparent=[%s]\n",
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
				&spans[i].Service,
				spans[i].Service.SDKLanguage.String(),
				traceparent(&spans[i]),
			)
		}
	}
}

func serializeSpansJSON(spans []request.Span, indent bool) ([]byte, error) {
	if indent {
		return json.MarshalIndent(spans, "", " ")
	}

	return json.Marshal(spans)
}

func jsonPrinter(input <-chan []request.Span, indent bool) {
	for spans := range input {
		data, err := serializeSpansJSON(spans, indent)

		if err != nil {
			mlog().Error("Error serializing span to json", "error", err)
			continue
		}

		fmt.Printf("%s\n", data)
	}
}

func traceparent(span *request.Span) string {
	if !trace.TraceID(span.TraceID).IsValid() {
		return ""
	}
	return fmt.Sprintf("00-%s-%s[%s]-%02x", trace.TraceID(span.TraceID).String(), trace.SpanID(span.SpanID).String(), trace.SpanID(span.ParentSpanID).String(), span.Flags)
}

func makeCounterPrinter() pipe.FinalFunc[[]request.Span] {
	counter := 0

	return func(input <-chan []request.Span) {
		for spans := range input {
			counter += len(spans)
		}

		fmt.Printf("Processed %d requests\n", counter)
	}
}

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package debug provides some export nodes that are aimed basically at debugging/testing
package debug

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
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
	input := in.Subscribe(msg.SubscriberName("textPrinter"))
	return func(ctx context.Context) {
		swarms.ForEachInput(ctx, input, nil, func(spans []request.Span) {
			for i := range spans {
				printSpan(&spans[i])
			}
		})
	}
}

func printSpan(span *request.Span) {
	t := span.Timings()

	pn := ""
	hn := ""

	if span.IsClientSpan() {
		if span.Service.UID.Namespace != "" {
			pn = "." + span.Service.UID.Namespace
		}
		if span.OtherNamespace != "" {
			hn = "." + span.OtherNamespace
		}
	} else {
		if span.OtherNamespace != "" {
			pn = "." + span.OtherNamespace
		}
		if span.Service.UID.Namespace != "" {
			hn = "." + span.Service.UID.Namespace
		}
	}

	r := ""
	if span.Route != "" {
		r = "(" + span.Route + ")"
	}

	fmt.Printf("%s (%s[%s]) %s(subType=%d) %v %s %s%s [%s:%d]->[%s:%d] contentLen:%dB responseLen:%dB svc=[%s %s] traceparent=[%s]\n",
		t.Start.Format("2006-01-02 15:04:05.12345"),
		t.End.Sub(t.RequestStart),
		t.End.Sub(t.Start),
		span.Type,
		span.SubType,
		span.Status,
		span.Method,
		span.Path,
		r,
		span.Peer+" as "+request.SpanPeer(span)+pn,
		span.PeerPort,
		span.Host+" as "+request.SpanHost(span)+hn,
		span.HostPort,
		span.ContentLength,
		span.ResponseLength,
		&span.Service,
		span.Service.SDKLanguage.String(),
		traceparent(span),
	)
}

func serializeSpansJSON(spans []request.Span, indent bool) ([]byte, error) {
	if indent {
		return json.MarshalIndent(spans, "", " ")
	}

	return json.Marshal(spans)
}

func jsonPrinter(in *msg.Queue[[]request.Span], indent bool) swarm.RunFunc {
	input := in.Subscribe(msg.SubscriberName("jsonPrinter"))
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
	input := in.Subscribe(msg.SubscriberName("counterPrinter"))
	counter := 0
	return func(_ context.Context) {
		for spans := range input {
			counter += len(spans)
		}

		fmt.Printf("Processed %d requests\n", counter)
	}
}

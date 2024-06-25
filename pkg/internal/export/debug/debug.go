// Package debug provides some export nodes that are aimed basically at debugging/testing
package debug

import (
	"fmt"

	"github.com/mariomac/pipes/pipe"
	"go.opentelemetry.io/otel/trace"

	"github.com/grafana/beyla/pkg/internal/request"
)

type PrintEnabled bool

func (p PrintEnabled) Enabled() bool {
	return bool(p)
}

func PrinterNode(e PrintEnabled) pipe.FinalProvider[[]request.Span] {
	return func() (pipe.FinalFunc[[]request.Span], error) {
		if !e {
			return pipe.IgnoreFinal[[]request.Span](), nil
		}
		return printFunc()
	}
}

func printFunc() (pipe.FinalFunc[[]request.Span], error) {
	return func(input <-chan []request.Span) {
		for spans := range input {
			for i := range spans {
				t := spans[i].Timings()
				fmt.Printf("%s (%s[%s]) %s %v %s %s [%s:%d]->[%s:%d] size:%dB svc=[%s %s] traceparent=[%s]\n",
					t.Start.Format("2006-01-02 15:04:05.12345"),
					t.End.Sub(t.RequestStart),
					t.End.Sub(t.Start),
					spanType(&spans[i]),
					spans[i].Status,
					spans[i].Method,
					spans[i].Path,
					spans[i].Peer+" as "+spans[i].PeerName,
					spans[i].PeerPort,
					spans[i].Host+" as "+spans[i].HostName,
					spans[i].HostPort,
					spans[i].ContentLength,
					&spans[i].ServiceID,
					spans[i].ServiceID.SDKLanguage.String(),
					traceparent(&spans[i]),
				)
			}
		}
	}, nil
}

func traceparent(span *request.Span) string {
	if !trace.TraceID(span.TraceID).IsValid() {
		return ""
	}
	return fmt.Sprintf("00-%s-%s-%02x", trace.TraceID(span.TraceID).String(), trace.SpanID(span.ParentSpanID).String(), span.Flags)
}

func spanType(span *request.Span) string {
	switch span.Type {
	case request.EventTypeHTTP:
		return "SRV"
	case request.EventTypeHTTPClient:
		return "CLNT"
	case request.EventTypeGRPC:
		return "GRPC_SRV"
	case request.EventTypeGRPCClient:
		return "GRPC_CLNT"
	case request.EventTypeSQLClient:
		return "SQL"
	case request.EventTypeRedisClient:
		return "REDIS"
	case request.EventTypeKafkaClient:
		return "KAFKA"
	case request.EventTypeRedisServer:
		return "REDIS_SRV"
	case request.EventTypeKafkaServer:
		return "KAFKA_SRV"
	}

	return ""
}

type NoopEnabled bool

func (n NoopEnabled) Enabled() bool {
	return bool(n)
}
func NoopNode(n NoopEnabled) pipe.FinalProvider[[]request.Span] {
	return func() (pipe.FinalFunc[[]request.Span], error) {
		if !n {
			return pipe.IgnoreFinal[[]request.Span](), nil
		}
		counter := 0
		return func(spans <-chan []request.Span) {
			for range spans {
				counter += len(spans)
			}
			fmt.Printf("Processed %d requests\n", counter)
		}, nil
	}
}

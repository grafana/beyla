// Package collector implements a test OTEL collector to use in unit tests
package collector

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
)

// TestCollector is a dummy OLTP test collector that allows retrieving part of the collected metrics
// Useful for unit testing
type TestCollector struct {
	ServerEndpoint string
	// TODO: add also traces history
	Records      chan MetricRecord
	TraceRecords chan TraceRecord
}

var log *slog.Logger

func init() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))
	log = slog.With("component", "collector.TestCollector")
}

func Start(ctx context.Context) (*TestCollector, error) {

	tc := TestCollector{
		Records:      make(chan MetricRecord, 100),
		TraceRecords: make(chan TraceRecord, 100),
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			log.Error("reading request body", err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		if request.URL.Path == "/v1/metrics" {
			tc.metricEvent(writer, body)
			return
		}
		if request.URL.Path == "/v1/traces" {
			tc.traceEvent(writer, body)
			return
		}
		slog.Info("unknown path " + request.URL.String())
		writer.WriteHeader(http.StatusNotFound)
	}))

	surl, err := url.Parse(server.URL)
	if err != nil {
		panic(err)
	}

	tc.ServerEndpoint = surl.String()

	go func() {
		<-ctx.Done()
		server.Close()
	}()

	return &tc, nil
}

func (tc *TestCollector) traceEvent(writer http.ResponseWriter, body []byte) {
	req := ptraceotlp.NewExportRequest()
	if err := req.UnmarshalProto(body); err != nil {
		log.Error("unmarshalling protobuf event", err)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	writer.WriteHeader(http.StatusOK)
	json, _ := req.MarshalJSON()
	slog.Debug("received metric", "json", string(json))

	forEach[ptrace.ResourceSpans](req.Traces().ResourceSpans(), func(rs ptrace.ResourceSpans) {
		forEach[ptrace.ScopeSpans](rs.ScopeSpans(), func(ss ptrace.ScopeSpans) {
			forEach[ptrace.Span](ss.Spans(), func(s ptrace.Span) {
				switch s.Kind() {
				case ptrace.SpanKindServer, ptrace.SpanKindInternal, ptrace.SpanKindClient:
					tr := TraceRecord{
						Kind:       s.Kind(),
						Name:       s.Name(),
						Attributes: map[string]string{},
					}
					s.Attributes().Range(func(k string, v pcommon.Value) bool {
						tr.Attributes[k] = v.AsString()
						return true
					})
					tr.Attributes["span_id"] = s.SpanID().String()
					tr.Attributes["parent_span_id"] = s.ParentSpanID().String()

					tc.TraceRecords <- tr
				default:
					slog.Warn("unsupported trace kind", "kind", s.Kind().String())
				}
			})
		})
	})
}

func (tc *TestCollector) metricEvent(writer http.ResponseWriter, body []byte) {
	req := pmetricotlp.NewExportRequest()
	if err := req.UnmarshalProto(body); err != nil {
		log.Error("unmarshalling protobuf event", err)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	writer.WriteHeader(http.StatusOK)
	json, _ := req.MarshalJSON()
	slog.Debug("received metric", "json", string(json))

	forEach[pmetric.ResourceMetrics](req.Metrics().ResourceMetrics(), func(rm pmetric.ResourceMetrics) {
		forEach[pmetric.ScopeMetrics](rm.ScopeMetrics(), func(sm pmetric.ScopeMetrics) {
			forEach[pmetric.Metric](sm.Metrics(), func(m pmetric.Metric) {
				switch m.Type() {
				case pmetric.MetricTypeHistogram:
					forEach[pmetric.HistogramDataPoint](m.Histogram().DataPoints(), func(hdp pmetric.HistogramDataPoint) {
						mr := MetricRecord{
							Name:       m.Name(),
							Unit:       m.Unit(),
							Type:       m.Type(),
							Attributes: map[string]string{},
						}
						hdp.Attributes().Range(func(k string, v pcommon.Value) bool {
							mr.Attributes[k] = v.AsString()
							return true
						})
						tc.Records <- mr
					})
				default:
					slog.Warn("unsupported metric type", "type", m.Type().String())
				}
			})
		})
	})
}

// MetricRecord stores some metadata from the received metrics
type MetricRecord struct {
	Attributes map[string]string
	Name       string
	Unit       string
	Type       pmetric.MetricType
}

type TraceRecord struct {
	Attributes map[string]string
	Name       string
	Kind       ptrace.SpanKind
}

type slice[T any] interface {
	At(int) T
	Len() int
}

func forEach[T any](sl slice[T], fn func(T)) {
	for i := 0; i < sl.Len(); i++ {
		fn(sl.At(i))
	}
}

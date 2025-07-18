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
	"sync/atomic"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"
)

// TestCollector is a dummy OLTP test collector that allows retrieving part of the collected metrics
// Useful for unit testing
type TestCollector struct {
	ServerEndpoint string
	// TODO: add also traces history
	records      atomic.Value // chan MetricRecord
	traceRecords atomic.Value // chan TraceRecord
}

var log *slog.Logger

func init() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))
	log = slog.With("component", "collector.TestCollector")
}

func Start(ctx context.Context) (*TestCollector, error) {
	tc := TestCollector{}
	tc.ResetRecords()
	tc.ResetTraceRecords()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			log.Error("reading request body", "error", err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		if request.URL.Path == "/v1/metrics" {
			log.Debug("/v1/metrics", "method", request.Method, "body", string(body))
			tc.metricEvent(writer, body)
			return
		}
		if request.URL.Path == "/v1/traces" {
			log.Debug("/v1/traces", "method", request.Method, "body", string(body))
			tc.traceEvent(writer, body)
			return
		}
		log.Info("unknown path " + request.Method + " " + request.URL.String())
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

	waitForServerAvailability(server)
	return &tc, nil
}

func waitForServerAvailability(server *httptest.Server) {
	// there is a race condition that is more visible in slow environment such as CI tests
	// the returned server is invoked for start in a background goroutine
	// and it might happen that a quick test tries to submit data to the server before it is started
	// failing the test
	serverCheckStart := time.Now()
	for {
		if resp, err := server.Client().Get(server.URL + "/are-you-ready"); err == nil && resp.StatusCode == http.StatusNotFound {
			log.Info("test collector started", "url", server.URL)
			return
		}
		if time.Since(serverCheckStart) > 5*time.Second {
			panic("collector.Start: timeout waiting for server to start")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (tc *TestCollector) traceEvent(writer http.ResponseWriter, body []byte) {
	req := ptraceotlp.NewExportRequest()
	if err := req.UnmarshalProto(body); err != nil {
		log.Error("unmarshalling protobuf event", "error", err)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	writer.WriteHeader(http.StatusOK)
	json, _ := req.MarshalJSON()
	log.Debug("received trace", "json", string(json))

	forEach[ptrace.ResourceSpans](req.Traces().ResourceSpans(), func(rs ptrace.ResourceSpans) {
		forEach[ptrace.ScopeSpans](rs.ScopeSpans(), func(ss ptrace.ScopeSpans) {
			forEach[ptrace.Span](ss.Spans(), func(s ptrace.Span) {
				switch s.Kind() {
				case ptrace.SpanKindServer, ptrace.SpanKindInternal, ptrace.SpanKindClient:
					tr := TraceRecord{
						Kind:               s.Kind(),
						Name:               s.Name(),
						Attributes:         map[string]string{},
						ResourceAttributes: map[string]string{},
					}
					s.Attributes().Range(func(k string, v pcommon.Value) bool {
						tr.Attributes[k] = v.AsString()
						return true
					})
					tr.Attributes["span_id"] = s.SpanID().String()
					tr.Attributes["parent_span_id"] = s.ParentSpanID().String()
					rs.Resource().Attributes().Range(func(k string, v pcommon.Value) bool {
						tr.ResourceAttributes[k] = v.AsString()
						return true
					})
					// remove ServiceInstanceIDKey to avoid flakiness
					delete(tr.ResourceAttributes, string(semconv.ServiceInstanceIDKey))
					tc.TraceRecords() <- tr
				default:
					log.Warn("unsupported trace kind", "kind", s.Kind().String())
				}
			})
		})
	})
}

func (tc *TestCollector) ResetRecords() {
	tc.records.Store(make(chan MetricRecord, 100))
}

func (tc *TestCollector) ResetTraceRecords() {
	tc.traceRecords.Store(make(chan TraceRecord, 100))
}

func (tc *TestCollector) Records() chan MetricRecord {
	return tc.records.Load().(chan MetricRecord)
}

func (tc *TestCollector) TraceRecords() chan TraceRecord {
	return tc.traceRecords.Load().(chan TraceRecord)
}

func (tc *TestCollector) metricEvent(writer http.ResponseWriter, body []byte) {
	req := pmetricotlp.NewExportRequest()
	if err := req.UnmarshalProto(body); err != nil {
		log.Error("unmarshalling protobuf event", "error", err)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	writer.WriteHeader(http.StatusOK)
	json, _ := req.MarshalJSON()
	log.Debug("received metric", "json", string(json))

	forEach[pmetric.ResourceMetrics](req.Metrics().ResourceMetrics(), func(rm pmetric.ResourceMetrics) {
		resourceAttrs := map[string]string{}
		rm.Resource().Attributes().Range(func(k string, v pcommon.Value) bool {
			resourceAttrs[k] = v.AsString()
			return true
		})

		forEach[pmetric.ScopeMetrics](rm.ScopeMetrics(), func(sm pmetric.ScopeMetrics) {
			forEach[pmetric.Metric](sm.Metrics(), func(m pmetric.Metric) {
				switch m.Type() {
				case pmetric.MetricTypeSum:
					forEach[pmetric.NumberDataPoint](m.Sum().DataPoints(), func(ndp pmetric.NumberDataPoint) {
						mr := MetricRecord{
							Name:               m.Name(),
							Unit:               m.Unit(),
							Type:               m.Type(),
							FloatVal:           ndp.DoubleValue(),
							IntVal:             ndp.IntValue(),
							Attributes:         map[string]string{},
							ResourceAttributes: resourceAttrs,
						}
						ndp.Attributes().Range(func(k string, v pcommon.Value) bool {
							mr.Attributes[k] = v.AsString()
							return true
						})
						tc.Records() <- mr
					})
				case pmetric.MetricTypeHistogram:
					forEach[pmetric.HistogramDataPoint](m.Histogram().DataPoints(), func(hdp pmetric.HistogramDataPoint) {
						// for simplicity, reporting only sum histogram data
						if !hdp.HasSum() {
							return
						}
						mr := MetricRecord{
							Name:               m.Name(),
							Unit:               m.Unit(),
							Type:               m.Type(),
							FloatVal:           hdp.Sum(),
							Count:              int(hdp.Count()),
							Attributes:         map[string]string{},
							ResourceAttributes: resourceAttrs,
						}
						hdp.Attributes().Range(func(k string, v pcommon.Value) bool {
							mr.Attributes[k] = v.AsString()
							return true
						})
						tc.Records() <- mr
					})
				case pmetric.MetricTypeGauge:
					forEach[pmetric.NumberDataPoint](m.Gauge().DataPoints(), func(ndp pmetric.NumberDataPoint) {
						mr := MetricRecord{
							Name:               m.Name(),
							Unit:               m.Unit(),
							Type:               m.Type(),
							Attributes:         map[string]string{},
							ResourceAttributes: resourceAttrs,
							FloatVal:           ndp.DoubleValue(),
							IntVal:             ndp.IntValue(),
						}
						ndp.Attributes().Range(func(k string, v pcommon.Value) bool {
							mr.Attributes[k] = v.AsString()
							return true
						})
						tc.Records() <- mr
					})
				default:
					log.Warn("unsupported metric type", "type", m.Type().String())
				}
			})
		})
	})
}

// MetricRecord stores some metadata from the received metrics
type MetricRecord struct {
	ResourceAttributes map[string]string
	Attributes         map[string]string
	Name               string
	Unit               string
	Type               pmetric.MetricType
	IntVal             int64
	FloatVal           float64
	Count              int
}

type TraceRecord struct {
	ResourceAttributes map[string]string
	Attributes         map[string]string
	Name               string
	Kind               ptrace.SpanKind
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

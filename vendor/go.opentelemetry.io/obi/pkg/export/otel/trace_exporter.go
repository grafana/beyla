// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/semaphore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"
	"google.golang.org/protobuf/proto"

	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	//nolint:depguard // The public OTLP client API requires protobuf resource spans.
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"

	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
)

const (
	defaultTraceQueueSize       = 1000
	defaultTraceWorkers         = 10
	defaultTraceFlushDelay      = 200 * time.Millisecond
	defaultTraceRetryStart      = 5 * time.Second
	defaultTraceRetryMax        = 30 * time.Second
	defaultTraceRetryTotal      = 5 * time.Minute
	defaultTraceRequestTimeout  = 5 * time.Second
	defaultTraceShutdownTimeout = 10 * time.Second
)

type traceSender = otelcfg.TracesExportFunc

type traceAttemptKey struct{}

type traceAttemptCount struct {
	failures atomic.Int64
}

func reportTraceAttempt(ctx context.Context, reporter imetrics.Reporter, err error) {
	if err == nil || reporter == nil || imetrics.IsBuiltinNoopReporter(reporter) {
		return
	}
	reporter.OTELTraceExportError(err)
	if count, ok := ctx.Value(traceAttemptKey{}).(*traceAttemptCount); ok {
		count.failures.Add(1)
	}
}

type traceRoundTripper struct {
	base     http.RoundTripper
	reporter imetrics.Reporter
}

func (t traceRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(request)
	if err != nil {
		reportTraceAttempt(request.Context(), t.reporter, err)
	} else if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		reportTraceAttempt(request.Context(), t.reporter, fmt.Errorf("trace export returned HTTP %d", response.StatusCode))
	}
	return response, err
}

type queuedTraces struct {
	traces ptrace.Traces
	spans  int64
}

type tracesExporter interface {
	Start(context.Context) error
	Shutdown(context.Context) error
	ConsumeTraces(context.Context, ptrace.Traces) error
}

type obiTracesExporter struct {
	send          traceSender
	client        otlptrace.Client
	reporter      imetrics.Reporter
	queue         chan queuedTraces
	queueSize     int64
	queueSlots    *semaphore.Weighted
	queueContext  context.Context
	queueCancel   context.CancelFunc
	workerCancel  context.CancelFunc
	queueMu       sync.RWMutex
	queueClosed   bool
	workerStarted bool
	batchMaxSize  int
	batchTimeout  time.Duration
	workerDone    chan struct{}
	shutdownOnce  sync.Once
}

func (e *obiTracesExporter) Start(ctx context.Context) error {
	e.queueMu.Lock()
	defer e.queueMu.Unlock()
	if e.queueClosed {
		return errors.New("trace exporter is shut down")
	}
	if e.client != nil {
		if err := e.client.Start(ctx); err != nil {
			return err
		}
	}
	if e.queue != nil && !e.workerStarted {
		e.workerStarted = true
		workerCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
		e.workerCancel = cancel
		go e.runQueue(workerCtx)
	}
	return nil
}

func (e *obiTracesExporter) Shutdown(ctx context.Context) error {
	var drainErr error
	e.shutdownOnce.Do(func() {
		if e.queue != nil {
			e.queueCancel()
			e.queueMu.Lock()
			e.queueClosed = true
			close(e.queue)
			started := e.workerStarted
			e.queueMu.Unlock()
			if started {
				select {
				case <-e.workerDone:
				case <-ctx.Done():
					drainErr = ctx.Err()
				}
				e.workerCancel()
			}
		} else {
			e.queueMu.Lock()
			e.queueClosed = true
			e.queueMu.Unlock()
		}
	})
	if e.client != nil {
		return errors.Join(drainErr, e.client.Stop(ctx))
	}
	return drainErr
}

func (e *obiTracesExporter) ConsumeTraces(ctx context.Context, traces ptrace.Traces) error {
	if e.queue != nil {
		return e.enqueue(ctx, traces)
	}
	e.queueMu.RLock()
	defer e.queueMu.RUnlock()
	if e.queueClosed {
		return errors.New("trace exporter is shut down")
	}
	return e.export(ctx, traces)
}

func (e *obiTracesExporter) enqueue(ctx context.Context, traces ptrace.Traces) error {
	spans := int64(max(1, traces.SpanCount()))
	if spans > e.queueSize {
		return errors.New("sending queue is full")
	}
	waitCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(e.queueContext, cancel)
	defer stop()
	if err := e.queueSlots.Acquire(waitCtx, spans); err != nil {
		return err
	}

	e.queueMu.RLock()
	defer e.queueMu.RUnlock()
	if e.queueClosed {
		e.queueSlots.Release(spans)
		return errors.New("trace exporter is shut down")
	}
	e.queue <- queuedTraces{traces: traces, spans: spans}
	return nil
}

func (e *obiTracesExporter) export(ctx context.Context, traces ptrace.Traces) error {
	spanCount := traces.SpanCount()
	attempts := &traceAttemptCount{}
	ctx = context.WithValue(ctx, traceAttemptKey{}, attempts)
	err := e.send(ctx, traces)
	if e.reporter != nil && !imetrics.IsBuiltinNoopReporter(e.reporter) {
		if err != nil && attempts.failures.Load() == 0 {
			e.reporter.OTELTraceExportError(err)
		} else if err == nil {
			e.reporter.OTELTraceExport(spanCount)
		}
	}
	return err
}

func (e *obiTracesExporter) runQueue(ctx context.Context) {
	defer close(e.workerDone)
	batches := make(chan ptrace.Traces)
	var workers sync.WaitGroup
	for range defaultTraceWorkers {
		workers.Go(func() {
			for batch := range batches {
				if err := e.export(ctx, batch); err != nil {
					slog.Warn("error sending trace to consumer", "error", err)
				}
			}
		})
	}
	defer func() {
		close(batches)
		workers.Wait()
	}()
	batch := ptrace.NewTraces()
	batchSpans := 0
	var timer *time.Timer
	var timeout <-chan time.Time
	flush := func() {
		if batchSpans == 0 {
			return
		}
		select {
		case batches <- batch:
		case <-ctx.Done():
		}
		batch = ptrace.NewTraces()
		batchSpans = 0
		if timer != nil {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
		timeout = nil
	}
	for {
		select {
		case queued, ok := <-e.queue:
			if !ok {
				flush()
				return
			}
			e.queueSlots.Release(queued.spans)
			if e.batchMaxSize == 0 {
				for _, resource := range queued.traces.ResourceSpans().All() {
					resource.CopyTo(batch.ResourceSpans().AppendEmpty())
				}
				batchSpans += queued.traces.SpanCount()
				flush()
			} else {
				for _, resource := range queued.traces.ResourceSpans().All() {
					var dstResource ptrace.ResourceSpans
					haveResource := false
					for _, scope := range resource.ScopeSpans().All() {
						var dstScope ptrace.ScopeSpans
						haveScope := false
						for _, span := range scope.Spans().All() {
							if !haveResource {
								dstResource = batch.ResourceSpans().AppendEmpty()
								resource.Resource().CopyTo(dstResource.Resource())
								dstResource.SetSchemaUrl(resource.SchemaUrl())
								haveResource = true
							}
							if !haveScope {
								dstScope = dstResource.ScopeSpans().AppendEmpty()
								scope.Scope().CopyTo(dstScope.Scope())
								dstScope.SetSchemaUrl(scope.SchemaUrl())
								haveScope = true
							}
							span.CopyTo(dstScope.Spans().AppendEmpty())
							batchSpans++
							if batchSpans == e.batchMaxSize {
								flush()
								haveResource = false
								haveScope = false
							}
						}
					}
				}
			}
			if batchSpans > 0 && timeout == nil {
				if timer == nil {
					timer = time.NewTimer(e.batchTimeout)
				} else {
					timer.Reset(e.batchTimeout)
				}
				timeout = timer.C
			}
		case <-timeout:
			flush()
		}
	}
}

func newOBITracesExporter(cfg otelcfg.TracesConfig, reporter imetrics.Reporter, send traceSender, client otlptrace.Client) tracesExporter {
	exporter := &obiTracesExporter{
		send:     send,
		client:   client,
		reporter: reporter,
	}
	if cfg.QueueSize > 0 || cfg.BatchMaxSize > 0 || cfg.BatchTimeout > 0 {
		queueSize := cfg.QueueSize
		if queueSize == 0 {
			queueSize = defaultTraceQueueSize
		}
		exporter.queue = make(chan queuedTraces, queueSize)
		exporter.queueSize = int64(queueSize)
		exporter.queueSlots = semaphore.NewWeighted(int64(queueSize))
		exporter.queueContext, exporter.queueCancel = context.WithCancel(context.Background())
		exporter.workerDone = make(chan struct{})
		exporter.batchMaxSize = cfg.BatchMaxSize
		exporter.batchTimeout = cfg.BatchTimeout
		if exporter.batchTimeout == 0 {
			exporter.batchTimeout = defaultTraceFlushDelay
		}
	}
	return exporter
}

func getTracesExporter(_ context.Context, cfg otelcfg.TracesConfig, reporter imetrics.Reporter) (tracesExporter, error) {
	if cfg.TracesExport != nil {
		// The Collector callback consumes traces synchronously, before OBI's network batching.
		return newOBITracesExporter(otelcfg.TracesConfig{}, reporter, cfg.TracesExport, nil), nil
	}

	switch cfg.GetProtocol() {
	case otelcfg.ProtocolHTTPJSON, otelcfg.ProtocolHTTPProtobuf, "":
		client, err := newHTTPTraceClient(cfg, reporter)
		if err != nil {
			return nil, err
		}
		return newOTLPTracesExporter(cfg, reporter, client), nil
	case otelcfg.ProtocolGRPC:
		client, err := newGRPCTraceClient(cfg, reporter)
		if err != nil {
			return nil, err
		}
		return newOTLPTracesExporter(cfg, reporter, client), nil
	case otelcfg.ProtocolDebug:
		send := func(_ context.Context, traces ptrace.Traces) error {
			data, err := (&ptrace.JSONMarshaler{}).MarshalTraces(traces)
			if err != nil {
				return err
			}
			slog.Info("traces", "data", string(data))
			return nil
		}
		return newOBITracesExporter(otelcfg.TracesConfig{}, reporter, send, nil), nil
	default:
		return nil, fmt.Errorf("invalid protocol value: %q", cfg.GetProtocol())
	}
}

func newOTLPTracesExporter(cfg otelcfg.TracesConfig, reporter imetrics.Reporter, client otlptrace.Client) tracesExporter {
	send := func(ctx context.Context, traces ptrace.Traces) error {
		data, err := (&ptrace.ProtoMarshaler{}).MarshalTraces(traces)
		if err != nil {
			return err
		}
		var payload tracepb.TracesData
		if err := proto.Unmarshal(data, &payload); err != nil {
			return err
		}
		return client.UploadTraces(ctx, payload.ResourceSpans)
	}
	return newOBITracesExporter(cfg, reporter, send, client)
}

func traceRetrySettings(cfg otelcfg.TracesConfig) (time.Duration, time.Duration, time.Duration) {
	initial, maxInterval, maxElapsed := defaultTraceRetryStart, defaultTraceRetryMax, defaultTraceRetryTotal
	if cfg.BackOffInitialInterval > 0 {
		initial = cfg.BackOffInitialInterval
	}
	if cfg.BackOffMaxInterval > 0 {
		maxInterval = cfg.BackOffMaxInterval
	}
	if cfg.BackOffMaxElapsedTime > 0 {
		maxElapsed = cfg.BackOffMaxElapsedTime
	}
	return initial, maxInterval, maxElapsed
}

func newHTTPTraceClient(cfg otelcfg.TracesConfig, reporter imetrics.Reporter) (otlptrace.Client, error) {
	opts, err := otelcfg.HTTPTracesEndpointOptions(&cfg)
	if err != nil {
		return nil, err
	}
	initial, maxInterval, maxElapsed := traceRetrySettings(cfg)
	options := opts.AsTraceHTTP()
	if opts.URLPath == "" {
		// A pathless OTLP traces endpoint in the environment otherwise becomes "/".
		options = append(options, otlptracehttp.WithURLPath("/v1/traces"))
	}
	options = append(options,
		otlptracehttp.WithTimeout(defaultTraceRequestTimeout),
		otlptracehttp.WithRetry(otlptracehttp.RetryConfig{
			Enabled: true, InitialInterval: initial, MaxInterval: maxInterval, MaxElapsedTime: maxElapsed,
		}),
	)
	if cfg.GetCompression() == "gzip" {
		options = append(options, otlptracehttp.WithCompression(otlptracehttp.GzipCompression))
	} else if cfg.GetCompression() == "none" {
		options = append(options, otlptracehttp.WithCompression(otlptracehttp.NoCompression))
	}
	if cfg.GetProtocol() == otelcfg.ProtocolHTTPJSON {
		options = append(options, otlptracehttp.WithEncoding(otlptracehttp.EncodingJSON))
	}
	if opts.UnixSocketAddr != "" || (reporter != nil && !imetrics.IsBuiltinNoopReporter(reporter)) {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		if opts.UnixSocketAddr != "" {
			transport = otelcfg.UnixTransport(opts.UnixSocketAddr)
		} else {
			transport.TLSClientConfig, err = traceTLSConfig(opts.SkipTLSVerify)
			if err != nil {
				return nil, err
			}
		}
		client := &http.Client{Transport: transport, Timeout: defaultTraceRequestTimeout}
		if reporter != nil && !imetrics.IsBuiltinNoopReporter(reporter) {
			client.Transport = traceRoundTripper{base: transport, reporter: reporter}
		}
		options = append(options, otlptracehttp.WithHTTPClient(client))
	}
	return otlptracehttp.NewClient(options...), nil
}

func traceTLSConfig(skipVerify bool) (*tls.Config, error) {
	certFile := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE")
	if certFile == "" {
		certFile = os.Getenv("OTEL_EXPORTER_OTLP_CERTIFICATE")
	}
	clientCertFile := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_CLIENT_CERTIFICATE")
	clientKeyFile := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_CLIENT_KEY")
	if clientCertFile == "" || clientKeyFile == "" {
		clientCertFile = os.Getenv("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE")
		clientKeyFile = os.Getenv("OTEL_EXPORTER_OTLP_CLIENT_KEY")
	}
	if certFile == "" && clientCertFile == "" && !skipVerify {
		return nil, nil
	}
	config := &tls.Config{InsecureSkipVerify: skipVerify}
	if certFile != "" {
		data, err := os.ReadFile(certFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("no certificates found in %s", certFile)
		}
		config.RootCAs = pool
	}
	if clientCertFile != "" && clientKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
		if err != nil {
			return nil, err
		}
		config.Certificates = []tls.Certificate{cert}
	}
	return config, nil
}

func newGRPCTraceClient(cfg otelcfg.TracesConfig, reporter imetrics.Reporter) (otlptrace.Client, error) {
	opts, err := otelcfg.GRPCTracesEndpointOptions(&cfg)
	if err != nil {
		return nil, err
	}
	initial, maxInterval, maxElapsed := traceRetrySettings(cfg)
	options := opts.AsTraceGRPC()
	options = append(options,
		otlptracegrpc.WithTimeout(maxElapsed),
		otlptracegrpc.WithDialOption(grpc.WithChainUnaryInterceptor(traceRequestDeadline(defaultTraceRequestTimeout, reporter))),
		otlptracegrpc.WithRetry(otlptracegrpc.RetryConfig{
			Enabled: true, InitialInterval: initial, MaxInterval: maxInterval, MaxElapsedTime: maxElapsed,
		}),
	)
	if cfg.GetCompression() == "gzip" {
		options = append(options, otlptracegrpc.WithCompressor("gzip"))
	} else if cfg.GetCompression() == "none" {
		// WithCompressor("none") reports an error in the OTLP client.
		options = append(options, otlptracegrpc.WithDialOption(
			grpc.WithDefaultCallOptions(grpc.UseCompressor(encoding.Identity)),
		))
	}
	return otlptracegrpc.NewClient(options...), nil
}

// The gRPC client's WithTimeout covers retries, so each RPC needs its own deadline.
func traceRequestDeadline(timeout time.Duration, reporter imetrics.Reporter) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, conn *grpc.ClientConn, invoke grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		requestCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		err := invoke(requestCtx, method, req, reply, conn, opts...)
		reportTraceAttempt(ctx, reporter, err)
		return err
	}
}

var _ tracesExporter = (*obiTracesExporter)(nil)

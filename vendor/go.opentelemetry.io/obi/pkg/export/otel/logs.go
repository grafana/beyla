// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/hashicorp/golang-lru/v2/simplelru"
	"google.golang.org/grpc"

	"go.opentelemetry.io/collector/pdata/pcommon"
	logdata "go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/exceptions"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/tracesgen"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

const (
	logsRequestTimeout  = 5 * time.Second
	logsExportTimeout   = 5 * time.Minute
	logsShutdownTimeout = 10 * time.Second
	logsLoggerCacheSize = 1024
)

// ExceptionLogsReceiver exports exception observations independently of request spans.
func ExceptionLogsReceiver(info *global.ContextInfo, cfg otelcfg.LogsConfig, selection attributes.Selection, input *msg.Queue[[]exceptions.Event]) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if input == nil || !cfg.Enabled() {
			return swarm.EmptyRunFunc()
		}
		if err := cfg.Validate(); err != nil {
			return nil, err
		}
		exporter, err := newLogsExporter(ctx, cfg)
		if err != nil {
			return nil, err
		}
		exportCtx, cancelExport := context.WithCancel(context.WithoutCancel(ctx))
		processor := sdklog.NewBatchProcessor(&logsExporterLifetime{Exporter: exporter, ctx: exportCtx},
			sdklog.WithMaxQueueSize(cfg.QueueSize),
			sdklog.WithExportMaxBatchSize(cfg.BatchMaxSize),
			sdklog.WithExportInterval(cfg.BatchTimeout),
			sdklog.WithExportTimeout(logsExportTimeout),
		)
		emitter := newExceptionLogEmitter(processor)
		subscription := input.Subscribe(msg.SubscriberName("otel.ExceptionLogsReceiver"))
		return func(ctx context.Context) {
			defer cancelExport()
			defer func() {
				shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), logsShutdownTimeout)
				defer cancel()
				if err := processor.Shutdown(shutdownCtx); err != nil {
					slog.Warn("exception logs shutdown failed", "error", err)
				}
			}()
			swarms.ForEachInput(ctx, subscription, slog.Debug, func(events []exceptions.Event) {
				for i := range events {
					emitter.emit(ctx, info, selection, &events[i])
				}
			})
		}, nil
	}
}

// SDK batch exports use their own context. Cancel any in-flight export after
// the receiver's shutdown deadline, while allowing queued records to drain first.
type logsExporterLifetime struct {
	sdklog.Exporter
	ctx context.Context
}

func (e *logsExporterLifetime) Export(ctx context.Context, records []sdklog.Record) error {
	if err := e.ctx.Err(); err != nil {
		return err
	}
	exportCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(e.ctx, cancel)
	defer stop()
	defer cancel()
	return e.Exporter.Export(exportCtx, records)
}

type exceptionLogEmitter struct {
	processor sdklog.Processor
	loggers   *simplelru.LRU[attribute.Distinct, otellog.Logger]
}

func newExceptionLogEmitter(processor sdklog.Processor) *exceptionLogEmitter {
	loggers, _ := simplelru.NewLRU[attribute.Distinct, otellog.Logger](logsLoggerCacheSize, nil)
	return &exceptionLogEmitter{processor: processor, loggers: loggers}
}

func (e *exceptionLogEmitter) emit(ctx context.Context, info *global.ContextInfo, selection attributes.Selection, event *exceptions.Event) {
	if !event.Service.Exceptions.Enabled || !event.Service.ExportModes.CanExportLogs() || (event.Type == "" && event.Message == "") {
		return
	}
	attrs := otelcfg.GetAppResourceAttrs(&info.NodeMeta, &event.Service)
	attrs = append(attrs, otelcfg.ResourceAttrsFromEnv(&event.Service)...)
	attrs = append(attrs, info.ExtraResourceAttributes...)
	attrs = otelcfg.FilterResourceAttrs(attrs, selection)
	res := resource.NewWithAttributes(attr.OBISchemaURL, attrs...)
	key := res.Equivalent()
	logger, ok := e.loggers.Get(key)
	if !ok {
		// Providers hold resource metadata. The receiver owns the shared processor
		// and shuts it down once; cache eviction only releases the logger.
		provider := sdklog.NewLoggerProvider(sdklog.WithResource(res), sdklog.WithProcessor(e.processor),
			sdklog.WithAttributeCountLimit(-1), sdklog.WithAttributeValueLengthLimit(-1))
		logger = provider.Logger(reporterName)
		e.loggers.Add(key, logger)
	}
	var record otellog.Record
	record.SetEventName("exception")
	record.SetTimestamp(event.Timestamp)
	record.SetObservedTimestamp(event.ObservedTimestamp)
	if event.SeverityNumber >= 1 && event.SeverityNumber <= 24 {
		record.SetSeverity(otellog.Severity(event.SeverityNumber))
		record.SetSeverityText(strings.ToUpper(logdata.SeverityNumber(event.SeverityNumber).String()))
	}
	if event.Type != "" {
		record.AddAttributes(attribute.String("exception.type", event.Type))
	}
	if event.Message != "" {
		record.AddAttributes(attribute.String("exception.message", event.Message))
	}
	if event.Stacktrace != "" {
		record.AddAttributes(attribute.String("exception.stacktrace", event.Stacktrace))
	}
	// OBI discards spans for processes that export their own traces.
	var spanContext trace.SpanContext
	if event.TraceID.IsValid() && !event.Service.ExportsOTelTraces() {
		spanContext = trace.NewSpanContext(trace.SpanContextConfig{
			TraceID: event.TraceID, SpanID: event.SpanID, TraceFlags: event.TraceFlags,
		})
	}
	logger.Emit(trace.ContextWithSpanContext(ctx, spanContext), record)
}

func newLogsExporter(ctx context.Context, cfg otelcfg.LogsConfig) (sdklog.Exporter, error) {
	if cfg.LogsExport != nil {
		return &consumerLogsExporter{send: cfg.LogsExport}, nil
	}
	switch cfg.Protocol {
	case otelcfg.ProtocolDebug:
		return &consumerLogsExporter{send: writeLogsJSON}, nil
	case otelcfg.ProtocolHTTPProtobuf:
		client := &http.Client{Timeout: logsRequestTimeout, Transport: http.DefaultTransport.(*http.Transport).Clone()}
		opts := []otlploghttp.Option{
			otlploghttp.WithEndpointURL(cfg.Endpoint),
			otlploghttp.WithHeaders(cfg.Headers()),
			otlploghttp.WithTimeout(logsExportTimeout),
			otlploghttp.WithCompression(otlploghttp.NoCompression),
			otlploghttp.WithHTTPClient(client),
		}
		if cfg.Compression == "gzip" {
			opts = append(opts, otlploghttp.WithCompression(otlploghttp.GzipCompression))
		}
		if addr, _ := cfg.UnixSocket(); addr != "" {
			client.Transport = otelcfg.UnixTransport(addr)
			opts = append(opts, otlploghttp.WithEndpointURL("http://localhost/v1/logs"))
		} else {
			transport := client.Transport.(*http.Transport)
			tlsConfig, err := otlpTLSConfig("LOGS", false)
			if err != nil {
				return nil, err
			}
			transport.TLSClientConfig = tlsConfig
		}
		exporter, err := otlploghttp.New(ctx, opts...)
		if err != nil {
			return nil, err
		}
		return &httpLogsExporter{Exporter: exporter, client: client}, nil
	case otelcfg.ProtocolGRPC:
		opts := []otlploggrpc.Option{
			otlploggrpc.WithEndpointURL(cfg.Endpoint),
			otlploggrpc.WithHeaders(cfg.Headers()),
			otlploggrpc.WithTimeout(logsExportTimeout),
			otlploggrpc.WithDialOption(grpc.WithChainUnaryInterceptor(logsRequestDeadline)),
			otlploggrpc.WithCompressor(cfg.Compression),
		}
		if addr, target := cfg.UnixSocket(); addr != "" {
			opts = append(opts, otlploggrpc.WithEndpoint(target), otlploggrpc.WithInsecure())
		}
		return otlploggrpc.New(ctx, opts...)
	default:
		return nil, fmt.Errorf("unsupported logs protocol %q", cfg.Protocol)
	}
}

// The SDK does not close idle connections on an injected HTTP client.
type httpLogsExporter struct {
	sdklog.Exporter
	client *http.Client
}

func (e *httpLogsExporter) Shutdown(ctx context.Context) error {
	err := e.Exporter.Shutdown(ctx)
	e.client.CloseIdleConnections()
	return err
}

// consumerLogsExporter adapts SDK records for the in-process consumer and console.
type consumerLogsExporter struct {
	send    otelcfg.LogsExportFunc
	stopped atomic.Bool
}

func (e *consumerLogsExporter) Export(ctx context.Context, records []sdklog.Record) error {
	if e.stopped.Load() {
		return sdklog.ErrExporterShutdown
	}
	logs := logdata.NewLogs()
	for i := range records {
		r := &records[i]
		res := logs.ResourceLogs().AppendEmpty()
		res.SetSchemaUrl(r.Resource().SchemaURL())
		tracesgen.AttrsToMap(r.Resource().Attributes()).CopyTo(res.Resource().Attributes())
		scope := res.ScopeLogs().AppendEmpty()
		scope.Scope().SetName(r.InstrumentationScope().Name)
		record := scope.LogRecords().AppendEmpty()
		record.SetEventName(r.EventName())
		if !r.Timestamp().IsZero() {
			record.SetTimestamp(pcommon.NewTimestampFromTime(r.Timestamp()))
		}
		record.SetObservedTimestamp(pcommon.NewTimestampFromTime(r.ObservedTimestamp()))
		record.SetSeverityNumber(logdata.SeverityNumber(r.Severity()))
		record.SetSeverityText(r.SeverityText())
		record.SetTraceID(pcommon.TraceID(r.TraceID()))
		record.SetSpanID(pcommon.SpanID(r.SpanID()))
		record.SetFlags(logdata.LogRecordFlags(r.TraceFlags()))
		record.SetDroppedAttributesCount(uint32(r.DroppedAttributes()))
		attrs := make([]attribute.KeyValue, 0, r.AttributesLen())
		r.WalkAttributes(func(kv attribute.KeyValue) bool { attrs = append(attrs, kv); return true })
		tracesgen.AttrsToMap(attrs).CopyTo(record.Attributes())
	}
	return e.send(ctx, logs)
}

func (e *consumerLogsExporter) Shutdown(context.Context) error {
	e.stopped.Store(true)
	return nil
}

func (*consumerLogsExporter) ForceFlush(context.Context) error { return nil }

func writeLogsJSON(_ context.Context, logs logdata.Logs) error {
	data, err := (&logdata.JSONMarshaler{}).MarshalLogs(logs)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(data, '\n'))
	return err
}

// The SDK export timeout covers retries; each RPC has its own deadline.
func logsRequestDeadline(ctx context.Context, method string, req, reply any, conn *grpc.ClientConn, invoke grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	requestCtx, cancel := context.WithTimeout(ctx, logsRequestTimeout)
	defer cancel()
	return invoke(requestCtx, method, req, reply, conn, opts...)
}

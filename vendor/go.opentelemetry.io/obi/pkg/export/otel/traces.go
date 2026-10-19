// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"context"
	"log/slog"
	"time"

	expirable2 "github.com/hashicorp/golang-lru/v2/expirable"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/tracesgen"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

const reporterName = "go.opentelemetry.io/obi"

func otlog() *slog.Logger {
	return slog.With("component", "otel.TracesReceiver")
}

func makeTracesReceiver(
	cfg otelcfg.TracesConfig,
	spanMetricsEnabled bool,
	ctxInfo *global.ContextInfo,
	selectorCfg *attributes.SelectorConfig,
	input *msg.Queue[[]request.Span],
) *tracesOTELReceiver {
	return &tracesOTELReceiver{
		cfg:                cfg,
		ctxInfo:            ctxInfo,
		selectorCfg:        selectorCfg,
		is:                 instrumentations.NewInstrumentationSelection(cfg.Instrumentations),
		spanMetricsEnabled: spanMetricsEnabled,
		input:              input.Subscribe(msg.SubscriberName("otel.TracesReceiver")),
		attributeCache:     expirable2.NewLRU[svc.UID, []attribute.KeyValue](1024, nil, 5*time.Minute),
	}
}

// TracesReceiver creates a terminal node that consumes request.Spans and sends OpenTelemetry metrics to the configured consumers.
func TracesReceiver(
	ctxInfo *global.ContextInfo,
	cfg otelcfg.TracesConfig,
	spanMetricsEnabled bool,
	selectorCfg *attributes.SelectorConfig,
	input *msg.Queue[[]request.Span],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled() {
			return swarm.EmptyRunFunc()
		}
		tr := makeTracesReceiver(cfg, spanMetricsEnabled, ctxInfo, selectorCfg, input)
		return tr.provideLoop, nil
	}
}

type tracesOTELReceiver struct {
	cfg                otelcfg.TracesConfig
	ctxInfo            *global.ContextInfo
	selectorCfg        *attributes.SelectorConfig
	is                 instrumentations.InstrumentationSelection
	spanMetricsEnabled bool
	attributeCache     *expirable2.LRU[svc.UID, []attribute.KeyValue]
	input              <-chan []request.Span
}

func (tr *tracesOTELReceiver) getConstantAttributes() (map[attr.Name]struct{}, error) {
	traceAttrs, err := tracesgen.UserSelectedAttributes(tr.selectorCfg)
	if err != nil {
		return nil, err
	}

	if tr.spanMetricsEnabled {
		traceAttrs[attr.SkipSpanMetrics] = struct{}{}
	}
	return traceAttrs, nil
}

func (tr *tracesOTELReceiver) processSpans(ctx context.Context, exp tracesExporter, spans []request.Span, traceAttrs map[attr.Name]struct{}, sampler trace.Sampler) {
	spanGroups := tracesgen.GroupSpans(ctx, spans, traceAttrs, sampler, tr.is, tr.selectorCfg.SensitiveQueryParamsCfg.Effective()...)

	for _, spanGroup := range spanGroups {
		if len(spanGroup) > 0 {
			sample := spanGroup[0]

			if !sample.Span.Service.ExportModes.CanExportTraces() {
				continue
			}

			envResourceAttrs := otelcfg.ResourceAttrsFromEnv(&sample.Span.Service)
			if tr.spanMetricsEnabled {
				envResourceAttrs = append(envResourceAttrs, attribute.Bool(string(attr.SkipSpanMetrics.OTEL()), true))
			}
			traces := tracesgen.GenerateTracesWithSelectedResourceAttributes(
				tr.attributeCache,
				&sample.Span.Service,
				envResourceAttrs,
				&tr.ctxInfo.NodeMeta,
				spanGroup,
				reporterName,
				tr.selectorCfg.SelectionCfg,
				tr.ctxInfo.ExtraResourceAttributes...)
			err := exp.ConsumeTraces(ctx, traces)
			if err != nil {
				// We can't do if errors.Is(err, queue.ErrQueueIsFull), since the queue package is internal
				if err.Error() == "sending queue is full" {
					// TODO: set this condition case to Warn once we make sure that
					// queueConfig.BlockOnOverflow = true works as expected
					slog.Debug("error sending trace to consumer", "error", err)
				} else {
					slog.Warn("error sending trace to consumer", "error", err)
				}
			}
		}
	}
}

func (tr *tracesOTELReceiver) provideLoop(ctx context.Context) {
	exp, err := getTracesExporter(ctx, tr.cfg, tr.ctxInfo.Metrics)
	if err != nil {
		slog.Error("error creating traces exporter", "error", err)
		return
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultTraceShutdownTimeout)
		defer cancel()
		err := exp.Shutdown(shutdownCtx)
		if err != nil {
			slog.Error("error shutting down traces exporter", "error", err)
		}
	}()
	err = exp.Start(ctx)
	if err != nil {
		slog.Error("error starting traces exporter", "error", err)
		return
	}

	traceAttrs, err := tr.getConstantAttributes()
	if err != nil {
		slog.Error("error selecting user trace attributes", "error", err)
		return
	}

	sampler := tr.cfg.SamplerConfig.Implementation()
	swarms.ForEachInput(ctx, tr.input, otlog().Debug, func(spans []request.Span) {
		tr.processSpans(ctx, exp, spans, traceAttrs, sampler)
	})
}

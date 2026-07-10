package otel

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	expirable2 "github.com/hashicorp/golang-lru/v2/expirable"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/meta"
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

const sigilGenerationIDKey = "sigil.generation.id"

func SigilExport(
	ctxInfo *global.ContextInfo,
	cfg *otelcfg.TracesConfig,
	selectorCfg *attributes.SelectorConfig,
	input *msg.Queue[[]request.Span],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		se := &sigilExport{
			log:            slog.With("component", "otel.SigilExport"),
			cfg:            cfg,
			nodeMeta:       &ctxInfo.NodeMeta,
			is:             instrumentations.NewInstrumentationSelection(cfg.Instrumentations),
			input:          input.Subscribe(msg.SubscriberName("otel.SigilExport")),
			attributeCache: expirable2.NewLRU[svc.UID, []attribute.KeyValue](1024, nil, 5*time.Minute),
		}
		traceAttrs, err := tracesgen.UserSelectedAttributes(selectorCfg)
		if err != nil {
			return nil, fmt.Errorf("sigil export: fetching user defined attributes: %w", err)
		}
		se.traceAttrs = traceAttrs
		return se.provideLoop, nil
	}
}

type sigilExport struct {
	log            *slog.Logger
	cfg            *otelcfg.TracesConfig
	nodeMeta       *meta.NodeMeta
	is             instrumentations.InstrumentationSelection
	input          <-chan []request.Span
	traceAttrs     map[attr.Name]struct{}
	attributeCache *expirable2.LRU[svc.UID, []attribute.KeyValue]
}

func (se *sigilExport) provideLoop(ctx context.Context) {
	exp, err := createTracesExporter(ctx, se.cfg, se.log)
	if err != nil {
		se.log.Error("error creating sigil traces exporter", "error", err)
		return
	}
	defer func() {
		if err := exp.Shutdown(ctx); err != nil {
			se.log.Error("error shutting down sigil traces exporter", "error", err)
		}
	}()
	if err := exp.Start(ctx, emptyHost{}); err != nil {
		se.log.Error("error starting sigil traces exporter", "error", err)
		return
	}

	sampler := se.cfg.SamplerConfig.Implementation()
	swarms.ForEachInput(ctx, se.input, se.log.Debug, func(spans []request.Span) {
		se.processSpans(ctx, exp, sampler, spans)
	})
}

func (se *sigilExport) processSpans(ctx context.Context, exp exporter.Traces, sampler sdktrace.Sampler, genAISpans []request.Span) {
	spanGroups := tracesgen.GroupSpans(ctx, genAISpans, se.traceAttrs, sampler, se.is)
	for _, spanGroup := range spanGroups {
		if len(spanGroup) == 0 {
			continue
		}
		sample := spanGroup[0]
		if !sample.Span.Service.ExportModes.CanExportTraces() {
			continue
		}
		envResourceAttrs := otelcfg.ResourceAttrsFromEnv(&sample.Span.Service)
		traces := tracesgen.GenerateTracesWithAttributes(
			se.attributeCache, &sample.Span.Service, envResourceAttrs, se.nodeMeta, spanGroup, ReporterName)
		// we must stamp the attributes for the conversation.id after we've generated the spans from OBI.
		// OBI has logic that sometimes it sets the conversation.id if it's available, in that case we want to
		// keep that id, otherwise we set the conversation.id to match the response.id.
		stampSigilRequiredAttributes(traces)
		se.log.Debug("exporting sigil traces", "count", traces.SpanCount())
		if err := exp.ConsumeTraces(ctx, traces); err != nil {
			se.log.Error("error sending trace to sigil exporter", "error", err)
		}
	}
}

func stampSigilRequiredAttributes(traces ptrace.Traces) {
	rs := traces.ResourceSpans()
	for i := 0; i < rs.Len(); i++ {
		scs := rs.At(i).ScopeSpans()
		for j := 0; j < scs.Len(); j++ {
			spans := scs.At(j).Spans()
			for k := 0; k < spans.Len(); k++ {
				attrs := spans.At(k).Attributes()
				attrs.PutStr(sigilGenerationIDKey, "gen_"+uuid.New().String())

				respID, ok := attrs.Get(string(semconv.GenAIResponseIDKey))
				if !ok {
					continue
				}
				if _, exists := attrs.Get(string(semconv.GenAIConversationIDKey)); !exists {
					attrs.PutStr(string(semconv.GenAIConversationIDKey), respID.Str())
				}
			}
		}
	}
}

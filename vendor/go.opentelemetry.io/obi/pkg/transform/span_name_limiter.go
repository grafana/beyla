// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform

import (
	"context"
	"log/slog"
	"slices"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/internal/helpers/cache"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

const aggregatedMark = "AGGREGATED"

type spanNameLimiter struct {
	limit int
	log   *slog.Logger
	in    <-chan []request.Span
	out   *msg.Queue[[]request.Span]

	spanNamesCount *cache.ExpirableLRU[svc.ServiceNameNamespace, *routesCount]
	ttl            time.Duration
}

type routesCount struct {
	routes map[string]struct{}
	// to save memory: when routes length reaches the per-service limit,
	// we can set it to nil to save memory and use this flag instead
	limitReached bool
}

type SpanNameLimiterConfig struct {
	Limit int
	OTEL  *otelcfg.MetricsConfig
	Prom  *prom.PrometheusConfig
}

// SpanNameLimiter applies only to metrics. If span metrics are enabled and
// metric_span_names_limit > 0, it renames all the span.name attributes when the cardinality of that attribute
// for a given, alive service exceeds max_span_names.
func SpanNameLimiter(cfg SpanNameLimiterConfig, input, output *msg.Queue[[]request.Span]) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if !enabled(&cfg) {
			return swarm.Bypass(input, output)
		}
		log := slog.With("component", "SpanNameLimiter")
		ttl := max(cfg.OTEL.TTL, cfg.Prom.TTL)
		return (&spanNameLimiter{
			limit: cfg.Limit,
			log:   log,
			in:    input.Subscribe(msg.SubscriberName("SpanNameLimiter")),
			out:   output,
			ttl:   ttl,
			spanNamesCount: cache.NewExpirableLRU[svc.ServiceNameNamespace, *routesCount](ttl,
				cache.WithEvictCallBack(func(key svc.ServiceNameNamespace, _ *routesCount) {
					log.Debug("evicting inactive service", "key", key)
				})),
		}).doLimit, nil
	}
}

func enabled(cfg *SpanNameLimiterConfig) bool {
	return cfg.Limit > 0 &&
		(slices.Contains(cfg.OTEL.Features, otelcfg.FeatureSpan) ||
			slices.Contains(cfg.Prom.Features, otelcfg.FeatureSpan))
}

func (l *spanNameLimiter) doLimit(ctx context.Context) {
	defer l.out.Close()
	l.log.Debug("Starting", "ttl", l.ttl, "limit", l.limit)
	expirer := time.NewTicker(l.ttl)
	for {
		select {
		case <-ctx.Done():
			l.log.Debug("context done. Stopping")
			return
		case <-expirer.C:
			removed := l.spanNamesCount.ExpireAll()
			l.log.Debug("inactive services expired", "len", removed)
		case spans := <-l.in:
			l.out.Send(l.aggregate(spans))
		}
	}
}

func (l *spanNameLimiter) aggregate(spans []request.Span) []request.Span {
	// assuming many spans from the same service could come in a row
	// we can slightly optimize by avoiding the cache lookup for each span
	var lastKey svc.ServiceNameNamespace
	lastCount := &routesCount{}

	output := spans
	alreadyCopying := false
	for i := 0; i < len(output); i++ {
		span := &output[i]
		if key := span.Service.UID.NameNamespace(); key != lastKey {
			lastKey = key
			count, ok := l.spanNamesCount.Get(key)
			if !ok {
				count = &routesCount{routes: map[string]struct{}{}}
				l.spanNamesCount.Put(key, count)
			}
			lastCount = count
		}
		if lastCount.limitReached {
			if !alreadyCopying {
				// optimization to minimize memory generation:
				// we only copy the input spans slice if we need to modify it to mark any
				// as aggregated (since we need to keep the original slice to report traces
				// unaggregated).
				// If no modification is needed, we keep using the original slice.
				alreadyCopying = true
				output = make([]request.Span, len(spans))
				copy(output, spans)
				span = &output[i]
			}
			span.OverrideTraceName = aggregatedMark
			continue
		}
		lastCount.routes[span.TraceName()] = struct{}{}
		if len(lastCount.routes) >= l.limit {
			// free some memory and set the flag
			lastCount.routes = nil
			lastCount.limitReached = true
		}
	}
	return output
}

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"context"
	"log/slog"

	appruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
)

type RuntimeMetricSender interface {
	SendGoRuntimeMetricRecord(context.Context, *ringbuf.Record, ServiceFilter) error
	SendJVMRuntimeMetrics(context.Context, []appruntime.JVMRuntimeEvent)
	SendNodejsRuntimeMetrics(context.Context, []appruntime.NodejsRuntimeEvent)
}

// RuntimeMetricRecordHandler lets tracers decode runtime metric records whose
// generated payload types live outside this package.
type RuntimeMetricRecordHandler func(context.Context, *ringbuf.Record) (bool, error)

func IsGoRuntimeMetricRecord(record *ringbuf.Record) bool {
	return record != nil &&
		len(record.RawSample) > 0 &&
		(record.RawSample[0] == EventTypeGoRuntimeMetric ||
			record.RawSample[0] == EventTypeGoRuntimeHistogram)
}

func HandleRuntimeMetricsRecord(
	ctx context.Context,
	eventContext *EBPFEventContext,
	record *ringbuf.Record,
	filter ServiceFilter,
	_ *slog.Logger,
	handlers ...RuntimeMetricRecordHandler,
) (bool, error) {
	if record == nil || len(record.RawSample) == 0 {
		return false, nil
	}

	eventType := record.RawSample[0]
	switch eventType {
	case EventTypeGoRuntimeMetric, EventTypeGoRuntimeHistogram:
		if eventContext == nil || eventContext.RuntimeMetrics == nil {
			return true, nil
		}
		return true, eventContext.RuntimeMetrics.SendGoRuntimeMetricRecord(ctx, record, filter)
	case EventTypeJVMMemoryPoolGC:
		for _, handler := range handlers {
			if handler == nil {
				continue
			}
			handled, err := handler(ctx, record)
			if err != nil {
				return true, err
			}
			if handled {
				return true, nil
			}
		}
		return true, nil
	case EventTypeNodejsEventLoop:
		if eventContext == nil || eventContext.RuntimeMetrics == nil {
			return true, nil
		}
		event, err := ParseNodejsEventLoopRecord(record)
		if err != nil {
			return true, err
		}
		if !DecorateNodejsRuntimeEvent(filter, &event) {
			return true, nil
		}
		eventContext.RuntimeMetrics.SendNodejsRuntimeMetrics(ctx, []appruntime.NodejsRuntimeEvent{event})
		return true, nil
	default:
		return false, nil
	}
}

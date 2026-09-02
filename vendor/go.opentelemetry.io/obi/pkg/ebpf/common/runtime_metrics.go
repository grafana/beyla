// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"context"
	"log/slog"
	"sync/atomic"

	appruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
)

var nextRuntimeMetricGeneration atomic.Uint64

// NewRuntimeMetricGeneration returns a process-lifetime identifier shared by runtime tracers.
func NewRuntimeMetricGeneration() uint64 {
	for {
		if generation := nextRuntimeMetricGeneration.Add(1); generation != 0 {
			return generation
		}
	}
}

type RuntimeMetricSender interface {
	SendGoRuntimeMetricRecord(context.Context, *ringbuf.Record, ServiceFilter) error
	SendPythonRuntimeMetricRecord(context.Context, *ringbuf.Record, ServiceFilter) error
	SendJVMGCMetrics(context.Context, []appruntime.JVMGCEvent)
	SendJVMRuntimeMetrics(context.Context, []appruntime.JVMRuntimeEvent)
	SendNodejsRuntimeMetrics(context.Context, []appruntime.NodejsRuntimeEvent)
	SendNodejsGCMetrics(context.Context, []appruntime.NodejsGCEvent)
	SendNodejsHeapSpaceMetrics(context.Context, []appruntime.NodejsHeapSpaceEvent)
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
	log *slog.Logger,
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
	case EventTypePythonRuntimeMetric:
		if eventContext == nil || eventContext.RuntimeMetrics == nil {
			return true, nil
		}
		return true, eventContext.RuntimeMetrics.SendPythonRuntimeMetricRecord(ctx, record, filter)
	case EventTypeJVMMemoryPoolGC, EventTypeJVMRuntimeMetrics:
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
	case EventTypeNodejsGC:
		if eventContext == nil || eventContext.RuntimeMetrics == nil {
			return true, nil
		}
		event, err := ParseNodejsGCRecord(record)
		if err != nil {
			return true, err
		}
		if event.GCType == appruntime.NodejsGCTypeUnknown {
			if log != nil {
				log.Debug("dropping nodejs gc event with unknown kind")
			}
			return true, nil
		}
		if !DecorateNodejsGCEvent(filter, &event) {
			return true, nil
		}
		eventContext.RuntimeMetrics.SendNodejsGCMetrics(ctx, []appruntime.NodejsGCEvent{event})
		return true, nil
	case EventTypeNodejsHeapSpace:
		if eventContext == nil || eventContext.RuntimeMetrics == nil {
			return true, nil
		}
		event, err := ParseNodejsHeapSpaceRecord(record)
		if err != nil {
			return true, err
		}
		if !appruntime.IsSemconvHeapSpace(event.SpaceName) {
			if log != nil {
				log.Debug("dropping nodejs heap-space event outside the semconv enum", "space", event.SpaceName)
			}
			return true, nil
		}
		if !DecorateNodejsHeapSpaceEvent(filter, &event) {
			return true, nil
		}
		eventContext.RuntimeMetrics.SendNodejsHeapSpaceMetrics(ctx, []appruntime.NodejsHeapSpaceEvent{event})
		return true, nil
	default:
		return false, nil
	}
}

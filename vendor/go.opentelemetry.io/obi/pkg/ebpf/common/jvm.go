// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"context"
	"log/slog"

	jvmruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
)

const (
	EventTypeGoRuntimeMetric = 17 // EVENT_GO_RUNTIME_METRIC
	EventTypeJVMMemoryPoolGC = 19 // EVENT_JVM_MEM_POOL_GC
)

type RuntimeMetricSender interface {
	SendGoRuntimeMetricRecord(context.Context, *ringbuf.Record, ServiceFilter) error
	SendJVMRuntimeMetrics(context.Context, []jvmruntime.JVMRuntimeEvent)
}

// RuntimeMetricRecordHandler lets tracers decode runtime metric records whose
// generated payload types live outside this package.
type RuntimeMetricRecordHandler func(context.Context, *ringbuf.Record) (bool, error)

func IsGoRuntimeMetricRecord(record *ringbuf.Record) bool {
	return record != nil &&
		len(record.RawSample) > 0 &&
		record.RawSample[0] == EventTypeGoRuntimeMetric
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
	case EventTypeGoRuntimeMetric:
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
	default:
		return false, nil
	}
}

func DecorateJVMRuntimeEvent(filter ServiceFilter, event *jvmruntime.JVMRuntimeEvent) bool {
	if filter == nil {
		return false
	}
	pids := filter.CurrentPIDs(PIDTypeKProbes)
	namespacePIDs, ok := pids[event.PIDNamespaceID]
	if !ok {
		return false
	}
	if service, ok := namespacePIDs[event.PID]; ok {
		event.Service = service
		return true
	}
	return false
}

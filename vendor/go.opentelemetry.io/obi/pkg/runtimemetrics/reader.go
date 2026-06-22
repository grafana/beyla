// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtimemetrics // import "go.opentelemetry.io/obi/pkg/runtimemetrics"

import (
	"context"
	"errors"
	"math"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	jvmruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

const EventTypeGoRuntimeMetric = ebpfcommon.EventTypeGoRuntimeMetric

func IsGoRuntimeMetricRecord(record *ringbuf.Record) bool {
	return ebpfcommon.IsGoRuntimeMetricRecord(record)
}

type RuntimeMetricSnapshot struct {
	Service svc.Attrs
	PID     app.PID
	Time    time.Time

	Go  *GoRuntimeMetricSnapshot
	JVM *JVMRuntimeMetricSnapshot
}

type GoRuntimeMetricSnapshot struct {
	MemoryLimit    *int64
	GCCycles       *uint64
	ProcessorLimit *int64
	GOGC           *int64
}

type JVMRuntimeMetricSnapshot struct {
	Kind       jvmruntime.JVMRuntimeMetricKind
	PoolName   string
	MemoryType jvmruntime.JVMMemoryType
	GCPhase    jvmruntime.JVMGCPhase
	ValueBytes uint64
}

type QueueSender struct {
	queue *msg.Queue[[]RuntimeMetricSnapshot]
}

func NewQueueSender(queue *msg.Queue[[]RuntimeMetricSnapshot]) *QueueSender {
	return &QueueSender{queue: queue}
}

func (s *QueueSender) SendGoRuntimeMetricRecord(
	ctx context.Context,
	record *ringbuf.Record,
	filter ebpfcommon.ServiceFilter,
) error {
	if s == nil || s.queue == nil {
		return nil
	}

	snapshot, ignore, err := SnapshotFromRingbuf(record, filter)
	if err != nil || ignore {
		return err
	}
	s.queue.SendCtx(ctx, []RuntimeMetricSnapshot{snapshot})
	return nil
}

func (s *QueueSender) SendJVMRuntimeMetrics(ctx context.Context, events []jvmruntime.JVMRuntimeEvent) {
	if s == nil || s.queue == nil || len(events) == 0 {
		return
	}

	snapshots := make([]RuntimeMetricSnapshot, 0, len(events))
	for i := range events {
		snapshots = append(snapshots, SnapshotFromJVMRuntimeEvent(events[i]))
	}
	s.queue.SendCtx(ctx, snapshots)
}

type goRuntimeMetricRawKey struct {
	HostPID uint32
	UserPID uint32
	Ns      uint32
}

type goRuntimeMetricRawEvent struct {
	Type     uint8
	Pad      [3]uint8
	PID      goRuntimeMetricRawKey
	Snapshot goRuntimeMetricRawSnapshot
}

type goRuntimeMetricRawSnapshot struct {
	NumGC       uint32
	NumForcedGC uint32
	GOMAXPROCS  int32
	GCPercent   int32
	MemoryLimit int64
}

func SnapshotFromRingbuf(
	record *ringbuf.Record,
	filter ebpfcommon.ServiceFilter,
) (RuntimeMetricSnapshot, bool, error) {
	if record == nil || len(record.RawSample) == 0 {
		return RuntimeMetricSnapshot{}, true, errors.New("invalid Go runtime metric event size")
	}
	if record.RawSample[0] != EventTypeGoRuntimeMetric {
		return RuntimeMetricSnapshot{}, true, nil
	}
	if filter == nil {
		return RuntimeMetricSnapshot{}, true, nil
	}

	event, err := ebpfcommon.ReinterpretCast[goRuntimeMetricRawEvent](record.RawSample)
	if err != nil {
		return RuntimeMetricSnapshot{}, true, err
	}
	service, ok := runtimeMetricService(filter.CurrentPIDs(ebpfcommon.PIDTypeGo), event.PID)
	if !ok {
		return RuntimeMetricSnapshot{}, true, nil
	}

	snapshot := convertGoRuntimeMetricSnapshot(service, app.PID(event.PID.UserPID), event.Snapshot)
	return snapshot, false, nil
}

func runtimeMetricService(
	currentPIDs map[uint32]map[app.PID]svc.Attrs,
	key goRuntimeMetricRawKey,
) (svc.Attrs, bool) {
	pids, ok := currentPIDs[key.Ns]
	if !ok {
		return svc.Attrs{}, false
	}
	service, ok := pids[app.PID(key.UserPID)]
	if !ok || !service.Features.AppRuntime() {
		return svc.Attrs{}, false
	}
	return service, true
}

func convertGoRuntimeMetricSnapshot(
	service svc.Attrs,
	pid app.PID,
	raw goRuntimeMetricRawSnapshot,
) RuntimeMetricSnapshot {
	total := uint64(raw.NumGC)
	var totalPtr *uint64
	if total > 0 {
		totalPtr = &total
	}

	var limit *int64
	if raw.MemoryLimit > 0 && raw.MemoryLimit < math.MaxInt64 {
		limit = &raw.MemoryLimit
	}

	var processorLimit *int64
	if raw.GOMAXPROCS > 0 {
		v := int64(raw.GOMAXPROCS)
		processorLimit = &v
	}
	var gogc *int64
	if raw.GCPercent >= 0 {
		v := int64(raw.GCPercent)
		gogc = &v
	}

	return RuntimeMetricSnapshot{
		Service: service,
		PID:     pid,
		Time:    time.Now(),
		Go: &GoRuntimeMetricSnapshot{
			MemoryLimit:    limit,
			GCCycles:       totalPtr,
			ProcessorLimit: processorLimit,
			GOGC:           gogc,
		},
	}
}

func SnapshotFromJVMRuntimeEvent(event jvmruntime.JVMRuntimeEvent) RuntimeMetricSnapshot {
	return RuntimeMetricSnapshot{
		Service: event.Service,
		PID:     event.PID,
		Time:    event.Time,
		JVM: &JVMRuntimeMetricSnapshot{
			Kind:       event.Kind,
			PoolName:   event.PoolName,
			MemoryType: event.MemoryType,
			GCPhase:    event.GCPhase,
			ValueBytes: event.ValueBytes,
		},
	}
}

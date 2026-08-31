// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtimemetrics // import "go.opentelemetry.io/obi/pkg/runtimemetrics"

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	appruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

const (
	EventTypeGoRuntimeMetric     = ebpfcommon.EventTypeGoRuntimeMetric
	EventTypeGoRuntimeHistogram  = ebpfcommon.EventTypeGoRuntimeHistogram
	EventTypePythonRuntimeMetric = ebpfcommon.EventTypePythonRuntimeMetric
)

func IsGoRuntimeMetricRecord(record *ringbuf.Record) bool {
	return ebpfcommon.IsGoRuntimeMetricRecord(record)
}

type RuntimeMetricSnapshot struct {
	Service    svc.Attrs
	PID        app.PID
	Generation uint64
	Time       time.Time
	// Removed marks a tombstone; its runtime-kind payload remains non-nil for routing.
	Removed bool

	Go              *GoRuntimeMetricSnapshot
	JVM             *JVMRuntimeMetricSnapshot
	Nodejs          *NodejsRuntimeMetricSnapshot
	NodejsGC        *NodejsGCSnapshot
	NodejsHeapSpace *NodejsHeapSpaceSnapshot
	Python          *PythonRuntimeMetricSnapshot

	Histogram *GoRuntimeHistogramSnapshot
}

// GoHistogramKind identifies a Go runtime timeHistogram source.
type GoHistogramKind uint8

const (
	// GoHistogramKindGCPause identifies stop-the-world GC pause durations.
	GoHistogramKindGCPause GoHistogramKind = iota
	// GoHistogramKindSchedLatency identifies runnable-to-running scheduler latency.
	GoHistogramKindSchedLatency
)

// GoRuntimeHistogramSnapshot contains the raw populations read from a Go runtime timeHistogram.
type GoRuntimeHistogramSnapshot struct {
	Kind      GoHistogramKind
	Counts    []uint64
	Underflow uint64
	Overflow  uint64
}

// CPythonGCGenerationCount matches the entries returned by gc.get_stats.
const CPythonGCGenerationCount = 3

type PythonRuntimeMetricSnapshot struct {
	Generations [CPythonGCGenerationCount]PythonGCGenerationMetrics
}

type PythonGCGenerationMetrics struct {
	Collections          uint64
	CollectedObjects     uint64
	UncollectableObjects uint64
}

type GoRuntimeMetricSnapshot struct {
	MemoryLimit       *int64
	GCCycles          *uint64
	ProcessorLimit    *int64
	GOGC              *int64
	CPUTime           *GoRuntimeCPUTimeSnapshot
	MemoryUsedStack   *int64
	MemoryUsedOther   *int64
	MemoryAllocated   *uint64
	MemoryAllocations *uint64
	GoroutineCount    *int64
	MemoryGCGoal      *int64
}

type GoRuntimeCPUTimeSnapshot struct {
	GCAssistTime       int64
	GCDedicatedTime    int64
	GCIdleTime         int64
	GCPauseTime        int64
	ScavengeAssistTime int64
	ScavengeBgTime     int64
	IdleTime           int64
	UserTime           int64
}

const goRuntimeCPUTimeValueCount = 8

type GoRuntimeCPUTimeValue struct {
	State         string
	DetailedState string
	Nanoseconds   int64
}

// GoRuntimeCPUTimeValues returns every CPU time series. A nil snapshot returns
// the same series with zero values so exporters can remove them consistently.
func GoRuntimeCPUTimeValues(cpu *GoRuntimeCPUTimeSnapshot) [goRuntimeCPUTimeValueCount]GoRuntimeCPUTimeValue {
	var snapshot GoRuntimeCPUTimeSnapshot
	if cpu != nil {
		snapshot = *cpu
	}

	return [...]GoRuntimeCPUTimeValue{
		{State: "user", Nanoseconds: snapshot.UserTime},
		{State: "gc", DetailedState: "gc/mark/assist", Nanoseconds: snapshot.GCAssistTime},
		{State: "gc", DetailedState: "gc/mark/dedicated", Nanoseconds: snapshot.GCDedicatedTime},
		{State: "gc", DetailedState: "gc/mark/idle", Nanoseconds: snapshot.GCIdleTime},
		{State: "gc", DetailedState: "gc/pause", Nanoseconds: snapshot.GCPauseTime},
		{State: "scavenge", DetailedState: "scavenge/assist", Nanoseconds: snapshot.ScavengeAssistTime},
		{State: "scavenge", DetailedState: "scavenge/background", Nanoseconds: snapshot.ScavengeBgTime},
		{State: "idle", Nanoseconds: snapshot.IdleTime},
	}
}

type JVMRuntimeMetricSnapshot struct {
	Kind          appruntime.JVMRuntimeMetricKind
	PoolName      string
	MemoryType    appruntime.JVMMemoryType
	GCPhase       appruntime.JVMGCPhase
	ValueBytes    uint64
	RuntimeValues *appruntime.JVMRuntimeValues
}

type NodejsRuntimeMetricSnapshot struct {
	appruntime.NodejsEventLoopValues
}

type NodejsGCSnapshot struct {
	GCType     appruntime.NodejsGCType
	DurationNs uint64
}

type NodejsHeapSpaceSnapshot struct {
	SpaceName string
	appruntime.NodejsHeapSpaceValues
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

func (s *QueueSender) SendPythonRuntimeMetricRecord(
	ctx context.Context,
	record *ringbuf.Record,
	filter ebpfcommon.ServiceFilter,
) error {
	if s == nil || s.queue == nil {
		return nil
	}

	snapshot, ignore, err := pythonSnapshotFromRingbuf(record, filter)
	if err != nil || ignore {
		return err
	}
	s.queue.SendCtx(ctx, []RuntimeMetricSnapshot{snapshot})
	return nil
}

func (s *QueueSender) SendNodejsRuntimeMetrics(ctx context.Context, events []appruntime.NodejsRuntimeEvent) {
	if s == nil || s.queue == nil || len(events) == 0 {
		return
	}

	snapshots := make([]RuntimeMetricSnapshot, 0, len(events))
	for i := range events {
		snapshots = append(snapshots, SnapshotFromNodejsRuntimeEvent(events[i]))
	}
	s.queue.SendCtx(ctx, snapshots)
}

func (s *QueueSender) SendNodejsGCMetrics(ctx context.Context, events []appruntime.NodejsGCEvent) {
	if s == nil || s.queue == nil || len(events) == 0 {
		return
	}

	snapshots := make([]RuntimeMetricSnapshot, 0, len(events))
	for i := range events {
		snapshots = append(snapshots, SnapshotFromNodejsGCEvent(events[i]))
	}
	s.queue.SendCtx(ctx, snapshots)
}

func (s *QueueSender) SendNodejsHeapSpaceMetrics(ctx context.Context, events []appruntime.NodejsHeapSpaceEvent) {
	if s == nil || s.queue == nil || len(events) == 0 {
		return
	}

	snapshots := make([]RuntimeMetricSnapshot, 0, len(events))
	for i := range events {
		snapshots = append(snapshots, SnapshotFromNodejsHeapSpaceEvent(events[i]))
	}
	s.queue.SendCtx(ctx, snapshots)
}

func (s *QueueSender) SendJVMGCMetrics(ctx context.Context, events []appruntime.JVMGCEvent) {
	if s == nil || s.queue == nil || len(events) == 0 {
		return
	}

	snapshots := make([]RuntimeMetricSnapshot, 0, len(events))
	for i := range events {
		snapshots = append(snapshots, SnapshotFromJVMGCEvent(events[i]))
	}
	s.queue.SendCtx(ctx, snapshots)
}

func (s *QueueSender) SendJVMRuntimeMetrics(ctx context.Context, events []appruntime.JVMRuntimeEvent) {
	if s == nil || s.queue == nil || len(events) == 0 {
		return
	}

	snapshots := make([]RuntimeMetricSnapshot, 0, len(events))
	for i := range events {
		snapshots = append(snapshots, SnapshotFromJVMRuntimeEvent(events[i]))
	}
	s.queue.SendCtx(ctx, snapshots)
}

// PythonRuntimeMetricsFromProcessEvent returns the final value before its tombstone.
func PythonRuntimeMetricsFromProcessEvent(event exec.ProcessEvent) []RuntimeMetricSnapshot {
	if event.Type != exec.ProcessEventTerminated || event.File == nil {
		return nil
	}
	service := event.ServiceFile().ServiceAttrs()
	snapshots := make([]RuntimeMetricSnapshot, 0, 2*len(event.FinalPythonRuntimeMetrics))
	for _, final := range event.FinalPythonRuntimeMetrics {
		processService := service
		processService.SDKLanguage = svc.InstrumentablePython
		processService.ProcPID = final.PID
		if final.HasValue {
			python := &PythonRuntimeMetricSnapshot{}
			for generation := range python.Generations {
				python.Generations[generation] = PythonGCGenerationMetrics{
					Collections:          final.Generations[generation].Collections,
					CollectedObjects:     final.Generations[generation].CollectedObjects,
					UncollectableObjects: final.Generations[generation].UncollectableObjects,
				}
			}
			snapshots = append(snapshots, RuntimeMetricSnapshot{
				Service: processService, PID: final.PID, Generation: final.Generation,
				Time: final.Time, Python: python,
			})
		}
		snapshots = append(snapshots, RuntimeMetricSnapshot{
			Service: processService, PID: final.PID, Generation: final.Generation,
			Time: final.Time, Removed: true, Python: &PythonRuntimeMetricSnapshot{},
		})
	}
	return snapshots
}

type goRuntimeMetricRawKey struct {
	HostPID uint32
	UserPID uint32
	Ns      uint32
}

type pythonRuntimeMetricRawEvent struct {
	Type     uint8
	Pad      [3]uint8
	PID      goRuntimeMetricRawKey
	Snapshot pythonRuntimeMetricRawSnapshot
}

type pythonRuntimeMetricRawSnapshot struct {
	Generation  uint64
	Generations [CPythonGCGenerationCount]pythonGCGenerationRawMetrics
}

type pythonGCGenerationRawMetrics struct {
	Collections   uint64
	Collected     uint64
	Uncollectable uint64
}

func pythonSnapshotFromRingbuf(
	record *ringbuf.Record,
	filter ebpfcommon.ServiceFilter,
) (RuntimeMetricSnapshot, bool, error) {
	if record == nil || filter == nil {
		return RuntimeMetricSnapshot{}, true, nil
	}
	event, err := ebpfcommon.ReinterpretCast[pythonRuntimeMetricRawEvent](record.RawSample)
	if err != nil {
		return RuntimeMetricSnapshot{}, true, err
	}
	if event.Type != EventTypePythonRuntimeMetric {
		return RuntimeMetricSnapshot{}, true, nil
	}
	service, ok := runtimeMetricService(filter.CurrentPIDs(ebpfcommon.PIDTypeKProbes), event.PID)
	if !ok {
		return RuntimeMetricSnapshot{}, true, nil
	}

	pid := app.PID(event.PID.HostPID)
	service.SDKLanguage = svc.InstrumentablePython
	service.ProcPID = pid
	python := &PythonRuntimeMetricSnapshot{}
	for generation, raw := range event.Snapshot.Generations {
		python.Generations[generation] = PythonGCGenerationMetrics{
			Collections:          raw.Collections,
			CollectedObjects:     raw.Collected,
			UncollectableObjects: raw.Uncollectable,
		}
	}
	return RuntimeMetricSnapshot{
		Service: service, PID: pid, Generation: event.Snapshot.Generation, Python: python,
	}, false, nil
}

type goRuntimeMetricRawEvent struct {
	Type       uint8
	Pad        [3]uint8
	PID        goRuntimeMetricRawKey
	Generation uint64
	Snapshot   goRuntimeMetricRawSnapshot
}

type goRuntimeMetricRawSnapshot struct {
	ValidMask             uint64
	NumGC                 uint32
	Pad                   uint32
	GOMAXPROCS            int32
	GCPercent             int32
	MemoryLimit           int64
	CPUGCAssistTime       int64
	CPUGCDedicatedTime    int64
	CPUGCIdleTime         int64
	CPUGCPauseTime        int64
	CPUScavengeAssistTime int64
	CPUScavengeBgTime     int64
	CPUIdleTime           int64
	CPUUserTime           int64
	MemoryUsedStack       int64
	MemoryUsedOther       int64
	MemoryAllocated       uint64
	MemoryAllocations     uint64
	GoroutineCount        int64
	MemoryGCGoal          uint64
}

const goRuntimeHistogramMaxBuckets = timeHistogramNumBuckets * timeHistogramNumSubBuckets

type goRuntimeHistogramRawEvent struct {
	Type        uint8
	Kind        GoHistogramKind
	Pad         [2]uint8
	PID         goRuntimeMetricRawKey
	BucketCount uint32
	Pad2        uint32
	Underflow   uint64
	Overflow    uint64
	Generation  uint64
	Counts      [goRuntimeHistogramMaxBuckets]uint64
}

// Mirrors the scalar bits of go_runtime_metric_valid_t in bpf/gotracer/maps/runtime.h.
// Check these bits before using raw values; zero can be a valid value.
const (
	goRuntimeMetricValidGCCycles       uint64 = 1 << 0
	goRuntimeMetricValidMemoryLimit    uint64 = 1 << 1
	goRuntimeMetricValidProcessorLimit uint64 = 1 << 2
	goRuntimeMetricValidGOGC           uint64 = 1 << 3
	goRuntimeMetricValidCPUTime        uint64 = 1 << 4
	goRuntimeMetricValidMemoryUsed     uint64 = 1 << 5
	goRuntimeMetricValidMemoryAllocs   uint64 = 1 << 6
	goRuntimeMetricValidGoroutineCount uint64 = 1 << 9
	goRuntimeMetricValidMemoryGCGoal   uint64 = 1 << 10
)

func SnapshotFromRingbuf(
	record *ringbuf.Record,
	filter ebpfcommon.ServiceFilter,
) (RuntimeMetricSnapshot, bool, error) {
	if record == nil || len(record.RawSample) == 0 {
		return RuntimeMetricSnapshot{}, true, errors.New("invalid Go runtime metric event size")
	}

	switch record.RawSample[0] {
	case EventTypeGoRuntimeMetric:
		return scalarSnapshotFromRingbuf(record, filter)
	case EventTypeGoRuntimeHistogram:
		return histogramSnapshotFromRingbuf(record, filter)
	default:
		return RuntimeMetricSnapshot{}, true, nil
	}
}

func scalarSnapshotFromRingbuf(
	record *ringbuf.Record,
	filter ebpfcommon.ServiceFilter,
) (RuntimeMetricSnapshot, bool, error) {
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

	snapshot := convertGoRuntimeMetricSnapshot(service, app.PID(event.PID.HostPID), event.Snapshot)
	snapshot.Generation = event.Generation
	return snapshot, false, nil
}

func histogramSnapshotFromRingbuf(
	record *ringbuf.Record,
	filter ebpfcommon.ServiceFilter,
) (RuntimeMetricSnapshot, bool, error) {
	event, err := ebpfcommon.ReinterpretCast[goRuntimeHistogramRawEvent](record.RawSample)
	if err != nil {
		return RuntimeMetricSnapshot{}, true, fmt.Errorf("decode Go runtime histogram event: %w", err)
	}
	if event.BucketCount != goRuntimeHistogramMaxBuckets {
		return RuntimeMetricSnapshot{}, true, fmt.Errorf(
			"invalid Go runtime histogram bucket count %d (want %d)",
			event.BucketCount,
			goRuntimeHistogramMaxBuckets,
		)
	}
	if event.Kind != GoHistogramKindGCPause && event.Kind != GoHistogramKindSchedLatency {
		return RuntimeMetricSnapshot{}, true, fmt.Errorf("unsupported Go runtime histogram kind %d", event.Kind)
	}
	if filter == nil {
		return RuntimeMetricSnapshot{}, true, nil
	}

	service, ok := runtimeMetricService(filter.CurrentPIDs(ebpfcommon.PIDTypeGo), event.PID)
	if !ok {
		return RuntimeMetricSnapshot{}, true, nil
	}

	counts := make([]uint64, int(event.BucketCount))
	copy(counts, event.Counts[:event.BucketCount])
	return RuntimeMetricSnapshot{
		Service:    service,
		PID:        app.PID(event.PID.HostPID),
		Generation: event.Generation,
		Time:       time.Now(),
		Histogram: &GoRuntimeHistogramSnapshot{
			Kind:      event.Kind,
			Counts:    counts,
			Underflow: event.Underflow,
			Overflow:  event.Overflow,
		},
	}, false, nil
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
	if raw.ValidMask&goRuntimeMetricValidGCCycles != 0 {
		totalPtr = &total
	}

	var limit *int64
	if raw.ValidMask&goRuntimeMetricValidMemoryLimit != 0 && raw.MemoryLimit > 0 && raw.MemoryLimit < math.MaxInt64 {
		limit = &raw.MemoryLimit
	}

	var processorLimit *int64
	if raw.ValidMask&goRuntimeMetricValidProcessorLimit != 0 && raw.GOMAXPROCS > 0 {
		v := int64(raw.GOMAXPROCS)
		processorLimit = &v
	}
	var gogc *int64
	if raw.ValidMask&goRuntimeMetricValidGOGC != 0 && raw.GCPercent >= 0 {
		v := int64(raw.GCPercent)
		gogc = &v
	}
	var cpuTime *GoRuntimeCPUTimeSnapshot
	if raw.ValidMask&goRuntimeMetricValidCPUTime != 0 &&
		raw.CPUGCAssistTime >= 0 &&
		raw.CPUGCDedicatedTime >= 0 &&
		raw.CPUGCIdleTime >= 0 &&
		raw.CPUGCPauseTime >= 0 &&
		raw.CPUScavengeAssistTime >= 0 &&
		raw.CPUScavengeBgTime >= 0 &&
		raw.CPUIdleTime >= 0 &&
		raw.CPUUserTime >= 0 {
		cpuTime = &GoRuntimeCPUTimeSnapshot{
			GCAssistTime:       raw.CPUGCAssistTime,
			GCDedicatedTime:    raw.CPUGCDedicatedTime,
			GCIdleTime:         raw.CPUGCIdleTime,
			GCPauseTime:        raw.CPUGCPauseTime,
			ScavengeAssistTime: raw.CPUScavengeAssistTime,
			ScavengeBgTime:     raw.CPUScavengeBgTime,
			IdleTime:           raw.CPUIdleTime,
			UserTime:           raw.CPUUserTime,
		}
	}
	var memoryUsedStack *int64
	var memoryUsedOther *int64
	if raw.ValidMask&goRuntimeMetricValidMemoryUsed != 0 &&
		raw.MemoryUsedStack >= 0 &&
		raw.MemoryUsedOther >= 0 {
		memoryUsedStack = &raw.MemoryUsedStack
		memoryUsedOther = &raw.MemoryUsedOther
	}
	var memoryAllocated *uint64
	var memoryAllocations *uint64
	if raw.ValidMask&goRuntimeMetricValidMemoryAllocs != 0 {
		memoryAllocated = &raw.MemoryAllocated
		memoryAllocations = &raw.MemoryAllocations
	}
	var goroutineCount *int64
	if raw.ValidMask&goRuntimeMetricValidGoroutineCount != 0 && raw.GoroutineCount > 0 {
		goroutineCount = &raw.GoroutineCount
	}
	var memoryGCGoal *int64
	if raw.ValidMask&goRuntimeMetricValidMemoryGCGoal != 0 &&
		raw.MemoryGCGoal > 0 && raw.MemoryGCGoal <= math.MaxInt64 {
		value := int64(raw.MemoryGCGoal)
		memoryGCGoal = &value
	}

	return RuntimeMetricSnapshot{
		Service: service,
		PID:     pid,
		Time:    time.Now(),
		Go: &GoRuntimeMetricSnapshot{
			MemoryLimit:       limit,
			GCCycles:          totalPtr,
			ProcessorLimit:    processorLimit,
			GOGC:              gogc,
			CPUTime:           cpuTime,
			MemoryUsedStack:   memoryUsedStack,
			MemoryUsedOther:   memoryUsedOther,
			MemoryAllocated:   memoryAllocated,
			MemoryAllocations: memoryAllocations,
			GoroutineCount:    goroutineCount,
			MemoryGCGoal:      memoryGCGoal,
		},
	}
}

func SnapshotFromNodejsGCEvent(event appruntime.NodejsGCEvent) RuntimeMetricSnapshot {
	return RuntimeMetricSnapshot{
		Service: event.Service,
		PID:     event.PID,
		Time:    event.Time,
		NodejsGC: &NodejsGCSnapshot{
			GCType:     event.GCType,
			DurationNs: event.DurationNs,
		},
	}
}

func SnapshotFromNodejsHeapSpaceEvent(event appruntime.NodejsHeapSpaceEvent) RuntimeMetricSnapshot {
	return RuntimeMetricSnapshot{
		Service: event.Service,
		PID:     event.PID,
		Time:    event.Time,
		NodejsHeapSpace: &NodejsHeapSpaceSnapshot{
			SpaceName:             event.SpaceName,
			NodejsHeapSpaceValues: event.NodejsHeapSpaceValues,
		},
	}
}

func SnapshotFromNodejsRuntimeEvent(event appruntime.NodejsRuntimeEvent) RuntimeMetricSnapshot {
	return RuntimeMetricSnapshot{
		Service: event.Service,
		PID:     event.PID,
		Time:    event.Time,
		Nodejs: &NodejsRuntimeMetricSnapshot{
			NodejsEventLoopValues: event.NodejsEventLoopValues,
		},
	}
}

func SnapshotFromJVMGCEvent(event appruntime.JVMGCEvent) RuntimeMetricSnapshot {
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

func SnapshotFromJVMRuntimeEvent(event appruntime.JVMRuntimeEvent) RuntimeMetricSnapshot {
	values := event.Values
	return RuntimeMetricSnapshot{
		Service:    event.Service,
		PID:        event.PID,
		Generation: event.Generation,
		Time:       event.Time,
		JVM: &JVMRuntimeMetricSnapshot{
			RuntimeValues: &values,
		},
	}
}

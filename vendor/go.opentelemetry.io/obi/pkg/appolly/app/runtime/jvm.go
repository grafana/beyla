// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtime // import "go.opentelemetry.io/obi/pkg/appolly/app/runtime"

import (
	"bytes"
	"fmt"
	"math"
	"strings"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/ebpf/timing"
)

const JVMRawStringLen = 64

type JVMRuntimeMetricKind string

const (
	JVMMetricMemoryUsed            JVMRuntimeMetricKind = "jvm.memory.used"
	JVMMetricMemoryCommitted       JVMRuntimeMetricKind = "jvm.memory.committed"
	JVMMetricMemoryLimit           JVMRuntimeMetricKind = "jvm.memory.limit"
	JVMMetricMemoryUsedAfterLastGC JVMRuntimeMetricKind = "jvm.memory.used_after_last_gc"
)

type JVMMemoryType string

const (
	JVMMemoryTypeHeap    JVMMemoryType = "heap"
	JVMMemoryTypeNonHeap JVMMemoryType = "non_heap"
	JVMMemoryTypeUnknown JVMMemoryType = "unknown"
)

type JVMGCPhase string

const (
	JVMGCPhaseBefore JVMGCPhase = "before"
	JVMGCPhaseAfter  JVMGCPhase = "after"
)

type JVMRuntimeEvent struct {
	PID            app.PID
	PIDNamespaceID uint32
	Service        svc.Attrs
	Time           time.Time
	Kind           JVMRuntimeMetricKind
	PoolName       string
	MemoryType     JVMMemoryType
	GCPhase        JVMGCPhase
	ValueBytes     uint64
}

type jvmRuntimeClocks struct {
	clock     func() time.Time
	monoClock func() time.Duration
}

var jvmClocks = jvmRuntimeClocks{clock: time.Now, monoClock: timing.MonoTimeNow}

type RawJVMGCWhenType uint32

const (
	RawJVMGCWhenBefore RawJVMGCWhenType = iota
	RawJVMGCWhenAfter
	RawJVMGCWhenEndSentinel
)

func ParseJVMMemoryPoolEvent(
	timestamp uint64,
	nsPID uint32,
	pidNamespaceID uint32,
	gcWhenType RawJVMGCWhenType,
	used uint64,
	committed uint64,
	maxSize uint64,
	pool [JVMRawStringLen]byte,
) ([]JVMRuntimeEvent, error) {
	phase, err := parseRawJVMGCPhase(gcWhenType)
	if err != nil {
		return nil, err
	}

	poolName := DecodeJVMRawString(pool)
	memoryType := InferJVMMemoryType(poolName)
	base := JVMRuntimeEvent{
		PID:            app.PID(nsPID),
		PIDNamespaceID: pidNamespaceID,
		Time:           jvmKernelTime(timestamp),
		PoolName:       poolName,
		MemoryType:     memoryType,
		GCPhase:        phase,
	}

	events := []JVMRuntimeEvent{
		withJVMMetric(base, JVMMetricMemoryUsed, used),
		withJVMMetric(base, JVMMetricMemoryCommitted, committed),
	}
	if maxSize != math.MaxUint64 {
		events = append(events, withJVMMetric(base, JVMMetricMemoryLimit, maxSize))
	}
	if phase == JVMGCPhaseAfter {
		events = append(events, withJVMMetric(base, JVMMetricMemoryUsedAfterLastGC, used))
	}
	return events, nil
}

func jvmKernelTime(ktime uint64) time.Time {
	now := jvmClocks.clock()
	delta := jvmClocks.monoClock() - time.Duration(int64(ktime))
	return now.Add(-delta)
}

func DecodeJVMRawString(raw [JVMRawStringLen]byte) string {
	end := bytes.IndexByte(raw[:], 0)
	if end < 0 {
		end = len(raw)
	}
	return string(raw[:end])
}

func InferJVMMemoryType(poolName string) JVMMemoryType {
	name := strings.ToLower(poolName)
	for _, nonHeapName := range []string{"metaspace", "code", "compressed class"} {
		if strings.Contains(name, nonHeapName) {
			return JVMMemoryTypeNonHeap
		}
	}
	for _, heapName := range []string{"eden", "survivor", "old", "tenured", "young", "zheap", "shenandoah", "epsilon", "humongous"} {
		if strings.Contains(name, heapName) {
			return JVMMemoryTypeHeap
		}
	}
	return JVMMemoryTypeUnknown
}

func withJVMMetric(base JVMRuntimeEvent, kind JVMRuntimeMetricKind, value uint64) JVMRuntimeEvent {
	base.Kind = kind
	base.ValueBytes = value
	return base
}

func parseRawJVMGCPhase(raw RawJVMGCWhenType) (JVMGCPhase, error) {
	switch raw {
	case RawJVMGCWhenBefore:
		return JVMGCPhaseBefore, nil
	case RawJVMGCWhenAfter:
		return JVMGCPhaseAfter, nil
	default:
		return "", fmt.Errorf("unsupported JVM GC phase: %d", raw)
	}
}

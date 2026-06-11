// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtime // import "go.opentelemetry.io/obi/pkg/appolly/app/runtime"

import (
	"bytes"
	"encoding/binary"
	"errors"
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
	JVMMetricBeylaHeapUsed         JVMRuntimeMetricKind = "beyla.jvm.heap.used"
)

type JVMMemoryType string

const (
	JVMMemoryTypeHeap    JVMMemoryType = "heap"
	JVMMemoryTypeNonHeap JVMMemoryType = "non_heap"
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

type RawJVMMemoryPoolEvent struct {
	Timestamp      uint64
	GlobalPID      uint32
	GlobalTID      uint32
	NsPID          uint32
	NsTID          uint32
	PIDNamespaceID uint32
	GCWhenType     RawJVMGCWhenType
	InitSize       uint64
	Used           uint64
	Committed      uint64
	MaxSize        uint64
	Manager        [JVMRawStringLen]byte
	Pool           [JVMRawStringLen]byte
}

type RawJVMGCHeapSummaryEvent struct {
	Timestamp      uint64
	GlobalPID      uint32
	GlobalTID      uint32
	NsPID          uint32
	NsTID          uint32
	PIDNamespaceID uint32
	GCWhenType     RawJVMGCWhenType
	Used           uint64
}

func ParseJVMMemoryPoolEvent(raw RawJVMMemoryPoolEvent) ([]JVMRuntimeEvent, error) {
	phase, err := parseRawJVMGCPhase(raw.GCWhenType)
	if err != nil {
		return nil, err
	}

	poolName := DecodeJVMRawString(raw.Pool)
	memoryType := InferJVMMemoryType(poolName)
	base := JVMRuntimeEvent{
		PID:            app.PID(raw.NsPID),
		PIDNamespaceID: raw.PIDNamespaceID,
		Time:           jvmKernelTime(raw.Timestamp),
		PoolName:       poolName,
		MemoryType:     memoryType,
		GCPhase:        phase,
	}

	events := []JVMRuntimeEvent{
		withJVMMetric(base, JVMMetricMemoryUsed, raw.Used),
		withJVMMetric(base, JVMMetricMemoryCommitted, raw.Committed),
	}
	if raw.MaxSize != math.MaxUint64 {
		events = append(events, withJVMMetric(base, JVMMetricMemoryLimit, raw.MaxSize))
	}
	if phase == JVMGCPhaseAfter {
		events = append(events, withJVMMetric(base, JVMMetricMemoryUsedAfterLastGC, raw.Used))
	}
	return events, nil
}

func DecodeJVMMemoryPoolEvent(payload []byte) ([]JVMRuntimeEvent, error) {
	var raw RawJVMMemoryPoolEvent
	if err := readRawPayload(payload, &raw); err != nil {
		return nil, err
	}
	return ParseJVMMemoryPoolEvent(raw)
}

func ParseJVMGCHeapSummaryEvent(raw RawJVMGCHeapSummaryEvent) (JVMRuntimeEvent, error) {
	phase, err := parseRawJVMGCPhase(raw.GCWhenType)
	if err != nil {
		return JVMRuntimeEvent{}, err
	}
	return JVMRuntimeEvent{
		PID:            app.PID(raw.NsPID),
		PIDNamespaceID: raw.PIDNamespaceID,
		Time:           jvmKernelTime(raw.Timestamp),
		Kind:           JVMMetricBeylaHeapUsed,
		GCPhase:        phase,
		ValueBytes:     raw.Used,
	}, nil
}

func jvmKernelTime(ktime uint64) time.Time {
	now := jvmClocks.clock()
	delta := jvmClocks.monoClock() - time.Duration(int64(ktime))
	return now.Add(-delta)
}

func DecodeJVMGCHeapSummaryEvent(payload []byte) (JVMRuntimeEvent, error) {
	var raw RawJVMGCHeapSummaryEvent
	if err := readRawPayload(payload, &raw); err != nil {
		return JVMRuntimeEvent{}, err
	}
	return ParseJVMGCHeapSummaryEvent(raw)
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
	return ""
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

func readRawPayload[T any](payload []byte, dst *T) error {
	size := binary.Size(*dst)
	if size < 0 {
		return errors.New("raw JVM payload has unsupported variable size")
	}
	if len(payload) < size {
		return fmt.Errorf("raw JVM payload too short: got %d bytes, need %d", len(payload), size)
	}
	return binary.Read(bytes.NewReader(payload[:size]), binary.LittleEndian, dst)
}

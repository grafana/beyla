// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtime // import "go.opentelemetry.io/obi/pkg/appolly/app/runtime"

import (
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/ebpf/timing"
)

// NodejsEventLoopValues carries one sampling interval of event-loop metrics
// reported by the injected nodejs agent; field semantics are documented on
// the wire struct (bpf/generictracer/types/nodejs.h).
type NodejsEventLoopValues struct {
	ELUIdleNs     uint64
	ELUActiveNs   uint64
	DelayMinNs    uint64
	DelayMaxNs    uint64
	DelayMeanNs   uint64
	DelayStddevNs uint64
	DelayP50Ns    uint64
	DelayP90Ns    uint64
	DelayP99Ns    uint64
	DelayCount    uint64
}

type NodejsRuntimeEvent struct {
	PID            app.PID
	PIDNamespaceID uint32
	Service        svc.Attrs
	Time           time.Time

	NodejsEventLoopValues
}

func ParseNodejsEventLoopEvent(
	timestamp uint64,
	nsPID uint32,
	pidNamespaceID uint32,
	values NodejsEventLoopValues,
) NodejsRuntimeEvent {
	return NodejsRuntimeEvent{
		PID:                   app.PID(nsPID),
		PIDNamespaceID:        pidNamespaceID,
		Time:                  timing.KernelTime(timestamp),
		NodejsEventLoopValues: values,
	}
}

// NodejsGCType is the garbage-collection kind of one GC cycle. The numeric
// values are the OBI wire codes assigned in fdextractor.js — deliberately
// not the Node perf_hooks constants, whose values differ across Node
// versions; the strings are the semconv v8js.gc.type values.
type NodejsGCType uint8

const (
	NodejsGCTypeUnknown NodejsGCType = iota
	NodejsGCTypeMinor
	NodejsGCTypeMajor
	NodejsGCTypeIncremental
	NodejsGCTypeWeakCB
)

func (t NodejsGCType) String() string {
	switch t {
	case NodejsGCTypeMinor:
		return "minor"
	case NodejsGCTypeMajor:
		return "major"
	case NodejsGCTypeIncremental:
		return "incremental"
	case NodejsGCTypeWeakCB:
		return "weakcb"
	default:
		return "unknown"
	}
}

type NodejsGCEvent struct {
	PID            app.PID
	PIDNamespaceID uint32
	Service        svc.Attrs
	Time           time.Time

	GCType     NodejsGCType
	DurationNs uint64
}

// ParseNodejsGCEvent decodes one GC cycle; an unrecognized wire code yields
// NodejsGCTypeUnknown and is dropped by the dispatch layer.
func ParseNodejsGCEvent(
	timestamp uint64,
	nsPID uint32,
	pidNamespaceID uint32,
	kind uint8,
	durationNs uint64,
) NodejsGCEvent {
	gcType := NodejsGCType(kind)
	if gcType > NodejsGCTypeWeakCB {
		gcType = NodejsGCTypeUnknown
	}
	return NodejsGCEvent{
		PID:            app.PID(nsPID),
		PIDNamespaceID: pidNamespaceID,
		Time:           timing.KernelTime(timestamp),
		GCType:         gcType,
		DurationNs:     durationNs,
	}
}

// NodejsHeapSpaceValues carries one sample of one V8 heap space; field
// semantics are documented on the wire struct
// (bpf/generictracer/types/nodejs.h).
type NodejsHeapSpaceValues struct {
	SpaceSize          uint64
	SpaceUsedSize      uint64
	SpaceAvailableSize uint64
	PhysicalSpaceSize  uint64
}

// semconvHeapSpaces are the well-known members of the semconv
// v8js.heap.space.name enum. The enum is open (custom values are allowed by
// the spec), but V8 reports engine-version-dependent extra spaces
// (read_only_space, shared_space, trusted_space, ...); exporting only the
// well-known set keeps the series bounded across engine versions and the
// repo's weaver validation — which grades undocumented enum values as
// violations — at zero.
var semconvHeapSpaces = map[string]struct{}{
	"new_space":          {},
	"old_space":          {},
	"code_space":         {},
	"map_space":          {},
	"large_object_space": {},
}

// IsSemconvHeapSpace reports whether name is a documented member of the
// semconv v8js.heap.space.name enum.
func IsSemconvHeapSpace(name string) bool {
	_, ok := semconvHeapSpaces[name]
	return ok
}

type NodejsHeapSpaceEvent struct {
	PID            app.PID
	PIDNamespaceID uint32
	Service        svc.Attrs
	Time           time.Time

	// SpaceName is the V8-defined space name, passed through verbatim: the
	// space set is engine-version-dependent.
	SpaceName string

	NodejsHeapSpaceValues
}

func ParseNodejsHeapSpaceEvent(
	timestamp uint64,
	nsPID uint32,
	pidNamespaceID uint32,
	spaceName string,
	values NodejsHeapSpaceValues,
) NodejsHeapSpaceEvent {
	return NodejsHeapSpaceEvent{
		PID:                   app.PID(nsPID),
		PIDNamespaceID:        pidNamespaceID,
		Time:                  timing.KernelTime(timestamp),
		SpaceName:             spaceName,
		NodejsHeapSpaceValues: values,
	}
}

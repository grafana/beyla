// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"fmt"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	nodejsruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
)

// Mirrors struct nodejs_eventloop_event in bpf/generictracer/types/nodejs.h;
// keep the layouts in sync.
type nodejsEventLoopRawEvent struct {
	Type      uint8
	Pad       [7]uint8
	Timestamp uint64
	GlobalPid uint32
	GlobalTid uint32
	NsPid     uint32
	NsTid     uint32
	PidNsID   uint32
	Pad2      uint32
	Values    nodejsruntime.NodejsEventLoopValues
}

func ParseNodejsEventLoopRecord(record *ringbuf.Record) (nodejsruntime.NodejsRuntimeEvent, error) {
	raw, err := ReinterpretCast[nodejsEventLoopRawEvent](record.RawSample)
	if err != nil {
		return nodejsruntime.NodejsRuntimeEvent{}, err
	}
	return nodejsruntime.ParseNodejsEventLoopEvent(raw.Timestamp, raw.NsPid, raw.PidNsID, raw.Values), nil
}

// Mirrors struct nodejs_gc_event in bpf/generictracer/types/nodejs.h;
// keep the layouts in sync.
type nodejsGCRawEvent struct {
	Type       uint8
	Kind       uint8
	Pad        [6]uint8
	Timestamp  uint64
	GlobalPid  uint32
	GlobalTid  uint32
	NsPid      uint32
	NsTid      uint32
	PidNsID    uint32
	Pad2       uint32
	DurationNs uint64
}

const nodejsHeapSpaceNameMax = 32

// Mirrors struct nodejs_heap_space_event in bpf/generictracer/types/nodejs.h;
// keep the layouts in sync.
type nodejsHeapSpaceRawEvent struct {
	Type               uint8
	NameLen            uint8
	Pad                [6]uint8
	Timestamp          uint64
	GlobalPid          uint32
	GlobalTid          uint32
	NsPid              uint32
	NsTid              uint32
	PidNsID            uint32
	Pad2               uint32
	SpaceSize          uint64
	SpaceUsedSize      uint64
	SpaceAvailableSize uint64
	PhysicalSpaceSize  uint64
	SpaceName          [nodejsHeapSpaceNameMax]uint8
}

func ParseNodejsGCRecord(record *ringbuf.Record) (nodejsruntime.NodejsGCEvent, error) {
	raw, err := ReinterpretCast[nodejsGCRawEvent](record.RawSample)
	if err != nil {
		return nodejsruntime.NodejsGCEvent{}, err
	}
	return nodejsruntime.ParseNodejsGCEvent(raw.Timestamp, raw.NsPid, raw.PidNsID, raw.Kind, raw.DurationNs), nil
}

func ParseNodejsHeapSpaceRecord(record *ringbuf.Record) (nodejsruntime.NodejsHeapSpaceEvent, error) {
	raw, err := ReinterpretCast[nodejsHeapSpaceRawEvent](record.RawSample)
	if err != nil {
		return nodejsruntime.NodejsHeapSpaceEvent{}, err
	}
	if raw.NameLen == 0 || raw.NameLen > nodejsHeapSpaceNameMax {
		return nodejsruntime.NodejsHeapSpaceEvent{}, fmt.Errorf("invalid heap space name length %d", raw.NameLen)
	}
	return nodejsruntime.ParseNodejsHeapSpaceEvent(
		raw.Timestamp,
		raw.NsPid,
		raw.PidNsID,
		string(raw.SpaceName[:raw.NameLen]),
		nodejsruntime.NodejsHeapSpaceValues{
			SpaceSize:          raw.SpaceSize,
			SpaceUsedSize:      raw.SpaceUsedSize,
			SpaceAvailableSize: raw.SpaceAvailableSize,
			PhysicalSpaceSize:  raw.PhysicalSpaceSize,
		},
	), nil
}

// nodejsServiceFor resolves the instrumented service for a
// (pid namespace, namespaced pid) pair.
func nodejsServiceFor(filter ServiceFilter, pidNsID uint32, pid app.PID) (svc.Attrs, bool) {
	if filter == nil {
		return svc.Attrs{}, false
	}
	namespacePIDs, ok := filter.CurrentPIDs(PIDTypeKProbes)[pidNsID]
	if !ok {
		return svc.Attrs{}, false
	}
	service, ok := namespacePIDs[pid]
	return service, ok
}

func DecorateNodejsRuntimeEvent(filter ServiceFilter, event *nodejsruntime.NodejsRuntimeEvent) bool {
	service, ok := nodejsServiceFor(filter, event.PIDNamespaceID, event.PID)
	if ok {
		event.Service = service
	}
	return ok
}

func DecorateNodejsGCEvent(filter ServiceFilter, event *nodejsruntime.NodejsGCEvent) bool {
	service, ok := nodejsServiceFor(filter, event.PIDNamespaceID, event.PID)
	if ok {
		event.Service = service
	}
	return ok
}

func DecorateNodejsHeapSpaceEvent(filter ServiceFilter, event *nodejsruntime.NodejsHeapSpaceEvent) bool {
	service, ok := nodejsServiceFor(filter, event.PIDNamespaceID, event.PID)
	if ok {
		event.Service = service
	}
	return ok
}

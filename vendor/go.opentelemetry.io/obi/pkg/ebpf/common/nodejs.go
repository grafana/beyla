// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	nodejsruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
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

func DecorateNodejsRuntimeEvent(filter ServiceFilter, event *nodejsruntime.NodejsRuntimeEvent) bool {
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

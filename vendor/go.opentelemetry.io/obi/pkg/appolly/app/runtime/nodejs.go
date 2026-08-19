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

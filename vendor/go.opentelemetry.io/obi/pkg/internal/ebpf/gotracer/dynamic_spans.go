// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gotracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/gotracer"

import (
	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/config"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/customspan"
)

func (p *Tracer) LiveSpanDescriptors(span *config.CustomSpanSpec, cookie uint64) []*ebpfcommon.USDTProbeDesc {
	return p.customSpan.Descriptors(span, cookie, customspan.Programs{
		Start:  p.bpfObjects.ObiCustomSpanStart,
		End:    p.bpfObjects.ObiCustomSpanEnd,
		Single: p.bpfObjects.ObiCustomSpanEvent,
		Specs:  p.bpfObjects.ObiUsdtSpecs,
		IPs:    p.bpfObjects.ObiUsdtIpToSpecId,
	})
}

func (p *Tracer) RegisterLiveSpan(span *config.CustomSpanSpec, cookie uint64, id string, generation uint64) {
	p.customSpan.Register(span, cookie, id, generation)
}

func (p *Tracer) RemoveFailedLiveSpan(cookie uint64) {
	p.customSpan.Remove(cookie)
}

func (p *Tracer) LiveSpanInvocationMap() *ebpf.Map {
	return p.bpfObjects.ObiDynamicInvocations
}

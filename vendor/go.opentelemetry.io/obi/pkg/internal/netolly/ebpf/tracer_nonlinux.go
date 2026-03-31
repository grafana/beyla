// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"

import (
	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/tcmanager"
	"go.opentelemetry.io/obi/pkg/netolly/flowdef"
)

// prevents "unused" linter error in mac
var _ = chooseMapReader

type FlowFetcher struct{}

func NewFlowFetcher(
	_, _ int,
	_, _ bool,
	_ *tcmanager.InterfaceManager,
	_ flowdef.PortGuessPolicy,
	_ *config.EBPFTracer,
) (*FlowFetcher, error) {
	return nil, nil
}

func (m *FlowFetcher) Close() error {
	return nil
}

func (m *FlowFetcher) ReadRingBuf() (ringbuf.Record, error) {
	return ringbuf.Record{}, nil
}

func (m *FlowFetcher) LookupAndDeleteMap() map[NetFlowId]*NetFlowMetrics {
	return nil
}

func (m *FlowFetcher) FlowPacketStatsMap() *ebpf.Map {
	panic("this is never going to be executed")
}

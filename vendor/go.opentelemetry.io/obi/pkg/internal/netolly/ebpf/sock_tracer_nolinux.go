// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"

import (
	cebpf "github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/netolly/flowdef"
)

type SockFlowFetcher struct{}

func (s *SockFlowFetcher) Close() error {
	panic("this is never going to be executed")
}

func (s *SockFlowFetcher) LookupAndDeleteMap() map[NetFlowId]*NetFlowMetrics {
	panic("this is never going to be executed")
}

func (s *SockFlowFetcher) ReadRingBuf() (ringbuf.Record, error) {
	panic("this is never going to be executed")
}

func (s *SockFlowFetcher) LookupPacketStats() (NetPacketCount, error) {
	return NetPacketCount{}, ErrTracerTerminated
}

func (s *SockFlowFetcher) DebugEventsMap() *cebpf.Map {
	return nil
}

func NewSockFlowFetcher(
	_, _ int, _ flowdef.PortGuessPolicy, _ *config.EBPFTracer,
) (*SockFlowFetcher, error) {
	// avoids linter complaining
	return nil, nil
}

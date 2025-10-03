// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package ebpf

import (
	"time"

	"go.opentelemetry.io/obi/pkg/components/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/components/ebpf/tcmanager"
)

type FlowFetcher struct{}

func NewFlowFetcher(
	_, _ int,
	_, _ bool,
	_ *tcmanager.InterfaceManager,
	_ tcmanager.TCBackend,
	_ uint32,
	_, _ time.Duration,
	_, _ []string,
) (*FlowFetcher, error) {
	return nil, nil
}

func (m *FlowFetcher) Close() error {
	return nil
}

func (m *FlowFetcher) ReadRingBuf() (ringbuf.Record, error) {
	return ringbuf.Record{}, nil
}

func (m *FlowFetcher) LookupAndDeleteMap() map[NetFlowId][]NetFlowMetrics {
	return nil
}

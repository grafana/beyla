// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package ebpf

import (
	"go.opentelemetry.io/obi/pkg/components/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/components/ebpf/tcmanager"
)

type FlowFetcher struct{}

func NewFlowFetcher(_, _ int, _, _ bool, _ *tcmanager.InterfaceManager, _ tcmanager.TCBackend) (*FlowFetcher, error) {
	return nil, nil
}

func (m *FlowFetcher) Close() error {
	return nil
}

func (m *FlowFetcher) ReadInto(*ringbuf.Record) error {
	return nil
}

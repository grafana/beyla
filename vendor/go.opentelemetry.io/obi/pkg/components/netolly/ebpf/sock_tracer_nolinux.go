// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package ebpf

import (
	"go.opentelemetry.io/obi/pkg/components/ebpf/ringbuf"
)

type SockFlowFetcher struct{}

func (s *SockFlowFetcher) Close() error {
	panic("this is never going to be executed")
}

func (s *SockFlowFetcher) ReadInto(*ringbuf.Record) error {
	panic("this is never going to be executed")
}

func NewSockFlowFetcher(_, _ int) (*SockFlowFetcher, error) {
	return nil, nil
}

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package ebpf

import (
	"time"

	"go.opentelemetry.io/obi/pkg/components/ebpf/ringbuf"
)

type SockFlowFetcher struct{}

func (s *SockFlowFetcher) Close() error {
	panic("this is never going to be executed")
}

func (s *SockFlowFetcher) ReadInto(*ringbuf.Record) error {
	panic("this is never going to be executed")
}

func NewSockFlowFetcher(
	_, _ int,
	_ uint32,
	_, _ time.Duration,
	_, _ []string,
) (*SockFlowFetcher, error) {
	// avoids linter complaining
	_ = parseProtocolList
	_ = assignProtocolList
	return nil, nil
}

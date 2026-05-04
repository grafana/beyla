// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"structs"

	ciliumebpf "github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
)

type StatsFetcher struct{}

type StatsTCPRtt struct {
	_      structs.HostLayout
	Flags  uint8
	Pad    [3]uint8
	SrttUs uint32
	Conn   struct {
		_      structs.HostLayout
		S_addr [16]uint8 //nolint:revive,staticcheck
		D_addr [16]uint8 //nolint:revive,staticcheck
		S_port uint16    //nolint:revive,staticcheck
		D_port uint16    //nolint:revive,staticcheck
	}
}

type StatsTCPFailedConnection struct {
	_      structs.HostLayout
	Flags  uint8
	Reason uint8
	Pad    [2]uint8
	Conn   struct {
		_      structs.HostLayout
		S_addr [16]uint8 //nolint:revive,staticcheck
		D_addr [16]uint8 //nolint:revive,staticcheck
		S_port uint16    //nolint:revive,staticcheck
		D_port uint16    //nolint:revive,staticcheck
	}
}

func NewStatsFetcher(_ *config.EBPFTracer, _ *export.Features) (*StatsFetcher, error) {
	return nil, nil
}

// Close any resources that are taken
func (m *StatsFetcher) Close() error {
	return nil
}

func (m *StatsFetcher) StatsEventsMap() *ciliumebpf.Map {
	return nil
}

func (m *StatsFetcher) DebugEventsMap() *ciliumebpf.Map {
	return nil
}

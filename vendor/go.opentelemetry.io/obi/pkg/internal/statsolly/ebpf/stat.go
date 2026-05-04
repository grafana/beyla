// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"go.opentelemetry.io/obi/pkg/internal/pipe"
)

type StatType uint8

const (
	StatTypeTCPRtt StatType = iota + 1
	StatTypeTCPFailedConnection
)

type TCPFailReasonType string

const (
	Unknown           TCPFailReasonType = "unknown"
	ConnectionRefused TCPFailReasonType = "refused"
	ConnectionReset   TCPFailReasonType = "reset"
	TimedOut          TCPFailReasonType = "timed-out"
	HostUnreachable   TCPFailReasonType = "host-unreachable"
	NetUnreachable    TCPFailReasonType = "net-unreachable"
	Other             TCPFailReasonType = "other"
)

// TCPFailReasonTypeCode mirrors enum tcp_fail_reason in bpf/statsolly/tp_tcp.c.
type TCPFailReasonTypeCode uint8

const (
	CodeUnknown           TCPFailReasonTypeCode = 0
	CodeConnectionRefused TCPFailReasonTypeCode = 1
	CodeConnectionReset   TCPFailReasonTypeCode = 2
	CodeTimedOut          TCPFailReasonTypeCode = 3
	CodeHostUnreachable   TCPFailReasonTypeCode = 4
	CodeNetUnreachable    TCPFailReasonTypeCode = 5
	CodeOther             TCPFailReasonTypeCode = 255
)

// Stat contains accumulated metrics from a stat, with extra metadata
// that is added from the user space
// REMINDER: any attribute here must be also added to the functions StatGetters
// in pkg/internal/statsolly/ebpf/stat_getters.go and getDefinitions in
// pkg/export/attributes/attr_defs.go
type Stat struct {
	Type                StatType             `json:"type"`
	TCPRtt              *TCPRtt              `json:"-"`
	TCPFailedConnection *TCPFailedConnection `json:"-"`

	// Attrs of the flow record: source/destination, OBI IP, etc...
	CommonAttrs pipe.CommonAttrs
}

type TCPRtt struct {
	SrttUs uint32 `json:"srtt_us"`
}

type TCPFailedConnection struct {
	Reason uint8 `json:"reason"`
}

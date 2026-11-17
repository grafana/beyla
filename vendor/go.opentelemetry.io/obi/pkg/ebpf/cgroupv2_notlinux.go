// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package ebpf // import "go.opentelemetry.io/obi/pkg/ebpf"

import (
	"errors"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func AttachCgroupSockOps(prog *ebpf.Program, attach ebpf.AttachType) (link.Link, error) {
	return AttachCgroupSockOpsAtPath(prog, attach, "")
}

func AttachCgroupSockOpsAtPath(_ *ebpf.Program, _ ebpf.AttachType, _ string) (link.Link, error) {
	return nil, errors.New("cgroupv2 not supported on this platform")
}

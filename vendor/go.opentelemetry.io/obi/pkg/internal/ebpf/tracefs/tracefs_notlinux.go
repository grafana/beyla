// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package tracefs // import "go.opentelemetry.io/obi/pkg/internal/ebpf/tracefs"

import (
	"errors"
	"io"

	"github.com/cilium/ebpf"
)

func Attach(*ebpf.Program, Options) (io.Closer, error) {
	return nil, errors.New("tracefs probes are only supported on Linux")
}

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package uprobe // import "go.opentelemetry.io/obi/pkg/internal/ebpf/uprobe"

import (
	"errors"
	"io"

	"github.com/cilium/ebpf"
)

func attachTraceFS(string, *ebpf.Program, Options) (io.Closer, error) {
	return nil, errors.New("tracefs uprobes are only supported on Linux")
}

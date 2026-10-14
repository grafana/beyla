// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package uprobe // import "go.opentelemetry.io/obi/pkg/internal/ebpf/uprobe"

import (
	"errors"
	"fmt"
	"io"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/internal/ebpf/tracefs"
)

func attachTraceFS(path string, prog *ebpf.Program, opts Options) (io.Closer, error) {
	if path == "" {
		return nil, errors.New("attaching uprobe through tracefs: executable path is empty")
	}

	targets := make([]string, 0, len(opts.Addresses))
	for _, address := range opts.Addresses {
		targets = append(targets, traceFSTarget(path, address, opts.RefCtrOffset))
	}
	return tracefs.Attach(prog, tracefs.Options{
		Type:    tracefs.Uprobe,
		Targets: targets,
		PID:     opts.PID,
		Return:  opts.Return,
	})
}

func traceFSTarget(path string, address, refCtrOffset uint64) string {
	target := fmt.Sprintf("%s:%#x", path, address)
	if refCtrOffset != 0 {
		target += fmt.Sprintf("(%#x)", refCtrOffset)
	}
	return target
}

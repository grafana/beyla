// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package kprobe // import "go.opentelemetry.io/obi/pkg/internal/ebpf/kprobe"

import (
	"errors"
	"io"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/internal/ebpf/tracefs"
)

var attachPMU = func(symbol string, prog *ebpf.Program, ret bool) (io.Closer, error) {
	if ret {
		return link.Kretprobe(symbol, prog, nil)
	}
	return link.Kprobe(symbol, prog, nil)
}

var attachTraceFSEvent = tracefs.Attach

// Attach retries an EACCES from the PMU through tracefs, keeping the kernel's
// default maxactive for return probes.
func Attach(symbol string, prog *ebpf.Program, ret bool) (io.Closer, error) {
	return tracefs.WithFallback(tracefs.Kprobe,
		func() (io.Closer, error) { return attachPMU(symbol, prog, ret) },
		func() (io.Closer, error) { return attachTraceFS(symbol, prog, ret) },
	)
}

func attachTraceFS(symbol string, prog *ebpf.Program, ret bool) (io.Closer, error) {
	opts := tracefs.Options{Type: tracefs.Kprobe, Targets: []string{symbol}, Return: ret}
	closer, err := attachTraceFSEvent(prog, opts)
	if !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.EINVAL) {
		return closer, err
	}

	// Match Cilium's retry for syscall names such as sys_connect.
	if prefix := syscallPrefix(); prefix != "" {
		opts.Targets = []string{prefix + symbol}
		return attachTraceFSEvent(prog, opts)
	}
	return closer, err
}

func syscallPrefix() string {
	switch runtime.GOARCH {
	case "amd64":
		return "__x64_"
	case "arm64":
		return "__arm64_"
	default:
		return ""
	}
}

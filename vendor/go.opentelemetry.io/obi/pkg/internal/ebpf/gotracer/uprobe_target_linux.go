// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gotracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/gotracer"

import (
	"errors"
	"fmt"
	"runtime"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

func (p *Tracer) ResolveUprobeTarget(executable *link.Executable, offset uint64) (uint64, uint64, error) {
	if p == nil || executable == nil || p.bpfObjects.GoExecutableIdentityRequests == nil ||
		p.bpfObjects.ObiCaptureGoExecutableIdentity == nil {
		return 0, 0, errors.New("go executable identity resolver is unavailable")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	tid := uint32(unix.Gettid())
	identity := BpfGoExecutableKeyT{}
	if err := p.bpfObjects.GoExecutableIdentityRequests.Put(&tid, &identity); err != nil {
		return 0, 0, fmt.Errorf("requesting Go executable identity: %w", err)
	}
	defer func() {
		_ = p.bpfObjects.GoExecutableIdentityRequests.Delete(&tid)
	}()

	// This temporary link makes the kernel pass its real target inode to the
	// uprobe_register kprobe. The program is inert in the target process.
	temporaryProbe, err := executable.Uprobe(
		"",
		p.bpfObjects.ObiCaptureGoExecutableIdentity,
		&link.UprobeOptions{Address: offset},
	)
	if err != nil {
		return 0, 0, fmt.Errorf("registering temporary uprobe: %w", err)
	}
	defer temporaryProbe.Close()

	if err := p.bpfObjects.GoExecutableIdentityRequests.Lookup(&tid, &identity); err != nil {
		return 0, 0, fmt.Errorf("reading Go executable identity: %w", err)
	}
	if identity.Ino == 0 {
		return 0, 0, errors.New("the kernel did not report the Go executable identity")
	}

	return identity.Dev, identity.Ino, nil
}

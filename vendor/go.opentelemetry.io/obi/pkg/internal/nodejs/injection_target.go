// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

import (
	"fmt"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

// to be changed in tests
var openProcessHandle = procs.OpenProcessHandle

// InjectionTarget is a stable reference to the process incarnation discovery
// accepted. Injection is queued and runs long after that, so the numeric PID
// alone would let a recycled one be identified, signaled and injected in the
// original's place.
type InjectionTarget struct {
	Pid     app.PID
	Process *procs.ProcessHandle
}

// InjectionTargetFrom pins the process inspected by discovery. The caller owns
// the returned target and must close it if it is not handed to the injection
// queue.
func InjectionTargetFrom(ie *ebpf.Instrumentable) (InjectionTarget, error) {
	pid := ie.FileInfo.Pid()
	process, err := openProcessHandle(pid, ie.FileInfo.StartTime())
	if err != nil {
		return InjectionTarget{}, fmt.Errorf("capturing stable identity for process %d: %w", pid, err)
	}

	return InjectionTarget{Pid: pid, Process: process}, nil
}

func (t InjectionTarget) PID() app.PID {
	return t.Pid
}

func (t InjectionTarget) Close() error {
	if t.Process == nil {
		return nil
	}
	return t.Process.Close()
}

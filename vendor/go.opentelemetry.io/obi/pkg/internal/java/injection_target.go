// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package javaagent // import "go.opentelemetry.io/obi/pkg/internal/java"

import (
	"fmt"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

// to be changed in tests
var openProcessHandle = procs.OpenProcessHandle

// InjectionTarget is everything the injector reads about a process. Callers
// copy these values out of the Instrumentable up front, so injection can run
// concurrently with the rest of the discovery pipeline without sharing that
// object.
type InjectionTarget struct {
	Type                  svc.InstrumentableType
	Pid                   app.PID
	RuntimeMetricsEnabled bool
	// TempDirEnv is the process' TMPDIR, empty when it does not set one.
	TempDirEnv string
	// StartTime pins the target to one incarnation of Pid. Injection is queued
	// by numeric PID and can run long after discovery saw the process, so the
	// kernel may have recycled that PID for an unrelated program in the
	// meantime. Zero when the start time could not be read, in which case the
	// target cannot be identified and injection refuses it.
	StartTime uint64
	Process   *procs.ProcessHandle
}

// InjectionTargetFrom acquires a stable reference to the process incarnation
// inspected by discovery. The caller owns the returned target and must close
// it if it is not handed to the injection queue.
func InjectionTargetFrom(ie *ebpf.Instrumentable) (InjectionTarget, error) {
	pid := ie.FileInfo.Pid()
	startTime := ie.FileInfo.StartTime()
	process, err := openProcessHandle(pid, startTime)
	if err != nil {
		return InjectionTarget{}, fmt.Errorf("capturing stable identity for process %d: %w", pid, err)
	}

	return InjectionTarget{
		Type:                  ie.Type,
		Pid:                   pid,
		RuntimeMetricsEnabled: ie.FileInfo.ServiceAttrs().Features.AppRuntime(),
		TempDirEnv:            ie.FileInfo.ServiceAttrs().EnvVars["TMPDIR"],
		StartTime:             startTime,
		Process:               process,
	}, nil
}

func (t InjectionTarget) Close() error {
	if t.Process == nil {
		return nil
	}
	return t.Process.Close()
}

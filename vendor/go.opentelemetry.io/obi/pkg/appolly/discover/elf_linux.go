// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"debug/elf"
	"fmt"
	"os"
	"syscall"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

func FindINodeForPID(pid app.PID) (dev uint64, ino uint64, err error) {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	info, err := os.Stat(exePath)
	if err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return 0, 0, fmt.Errorf("couldn't cast stat into syscall.Stat_t for %s", exePath)
		}
		return stat.Dev, stat.Ino, nil
	}

	return 0, 0, err
}

func findExecElf(p *services.ProcessInfo, svcID *svc.Attrs) (*exec.FileInfo, error) {
	// In container environments or K8s, we can't just open the executable exe path, because it might
	// be in the volume of another pod/container. We need to access it through the /proc/<pid>/exe symbolic link
	ns, err := procs.FindNamespace(p.Pid)
	if err != nil {
		return nil, fmt.Errorf("can't find namespace for PID=%d: %w", p.Pid, err)
	}
	// TODO: allow overriding /proc root folder
	proExeLinkPath := fmt.Sprintf("/proc/%d/exe", p.Pid)
	elfFile, err := elf.Open(proExeLinkPath)
	if err != nil {
		return nil, fmt.Errorf("can't open ELF file in %s: %w", proExeLinkPath, err)
	}

	dev, ino, err := FindINodeForPID(p.Pid)
	if err != nil {
		return nil, err
	}

	envVars, err := procs.EnvVars(p.Pid)
	if err != nil {
		return nil, err
	}

	fi := exec.New(exec.Init{
		Service:        *svcID,
		CmdExePath:     p.ExePath,
		ProExeLinkPath: proExeLinkPath,
		ELF:            elfFile,
		Pid:            p.Pid,
		Ppid:           p.PPid,
		Dev:            dev,
		Ino:            ino,
		Ns:             ns,
	})
	fi.ApplyEnvVariables(envVars)
	return fi, nil
}

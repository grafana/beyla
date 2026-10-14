// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet // import "go.opentelemetry.io/obi/pkg/internal/dotnet"

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/internal/procs"
)

type diagnosticTarget struct {
	directory  *os.File
	socketPath string
	info       processInfo
}

// resolveDiagnosticTarget verifies a .NET diagnostic socket for the pinned
// process. The caller owns the returned directory and closes it after the
// EventPipe session's final control connection.
func resolveDiagnosticTarget(ctx context.Context, process *procs.ProcessHandle, tempDir string) (diagnosticTarget, error) {
	if err := ctx.Err(); err != nil {
		return diagnosticTarget{}, err
	}
	pids, err := process.NamespacedPids()
	if err != nil {
		return diagnosticTarget{}, fmt.Errorf("reading target namespace PIDs: %w", err)
	}
	if len(pids) == 0 || pids[len(pids)-1] == 0 {
		return diagnosticTarget{}, errors.New("target namespace PID is unavailable")
	}

	directory, err := openDiagnosticDirectory(process, tempDir)
	if err != nil {
		return diagnosticTarget{}, err
	}
	fdPath := fmt.Sprintf("/proc/self/fd/%d", directory.Fd())
	socketPath, info, err := resolveDiagnosticSocket(ctx, fdPath, uint64(pids[len(pids)-1]), process.StartTime())
	if err != nil {
		_ = directory.Close()
		return diagnosticTarget{}, err
	}
	if err := process.Alive(); err != nil {
		_ = directory.Close()
		return diagnosticTarget{}, fmt.Errorf("checking diagnostic target is alive: %w", err)
	}
	return diagnosticTarget{directory: directory, socketPath: socketPath, info: info}, nil
}

// openDiagnosticDirectory pins the target's temporary directory through its
// stable process handle. The caller keeps it open while using /proc/self/fd/<fd>
// for diagnostic socket lookup and subsequent EventPipe control connections.
func openDiagnosticDirectory(process *procs.ProcessHandle, tempDir string) (*os.File, error) {
	if tempDir == "" {
		tempDir = "/tmp"
	}
	if !filepath.IsAbs(tempDir) {
		return nil, fmt.Errorf("diagnostic TMPDIR must be absolute: %q", tempDir)
	}

	directory, err := process.Open(filepath.Join("root", filepath.Clean(tempDir)), unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return nil, fmt.Errorf("opening target diagnostic directory %q: %w", tempDir, err)
	}
	return directory, nil
}

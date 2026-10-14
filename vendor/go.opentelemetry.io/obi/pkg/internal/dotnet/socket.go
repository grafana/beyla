// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet // import "go.opentelemetry.io/obi/pkg/internal/dotnet"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var errUnsupportedRuntime = errors.New("unsupported CLR version")

// resolveDiagnosticSocket verifies socket candidates with ProcessInfo2 and
// selects one .NET 8+ runtime matching the expected namespace PID and process start time.
func resolveDiagnosticSocket(ctx context.Context, tempDir string, namespacePID, startTime uint64) (string, processInfo, error) {
	paths, err := findDiagnosticSockets(tempDir, namespacePID, startTime)
	if err != nil {
		return "", processInfo{}, err
	}
	var selected string
	var selectedInfo processInfo
	var failures []error
	unsupported := 0
	for _, path := range paths {
		info, err := queryProcessInfo2(ctx, path)
		if ctx.Err() != nil {
			return "", processInfo{}, ctx.Err()
		}
		if err != nil {
			if errors.Is(err, errIPCUnknownCommand) {
				unsupported++
			}
			failures = append(failures, fmt.Errorf("querying diagnostic socket %q: %w", path, err))
			continue
		}
		if info.PID != namespacePID {
			failures = append(failures, fmt.Errorf("diagnostic socket %q reports PID %d, expected %d", path, info.PID, namespacePID))
			continue
		}
		majorVersion, _, hasMinorVersion := strings.Cut(info.CLRVersion, ".")
		major, versionErr := strconv.ParseUint(majorVersion, 10, 32)
		if versionErr != nil || !hasMinorVersion || major < 8 {
			unsupported++
			failures = append(failures, fmt.Errorf("diagnostic socket %q reports %s %q", path, errUnsupportedRuntime.Error(), info.CLRVersion))
			continue
		}
		if selected != "" {
			return "", processInfo{}, fmt.Errorf("multiple diagnostic sockets match namespace PID %d", namespacePID)
		}
		selected, selectedInfo = path, info
	}
	if selected != "" {
		return selected, selectedInfo, nil
	}
	if len(failures) > 0 {
		// Stop retrying only when every candidate was identified as unsupported.
		if unsupported == len(paths) {
			failures = append(failures, errUnsupportedRuntime)
		}
		return "", processInfo{}, errors.Join(failures...)
	}
	return "", processInfo{}, fmt.Errorf("no diagnostic socket for namespace PID %d: %w", namespacePID, os.ErrNotExist)
}

// findDiagnosticSockets lists sockets matching a namespace PID and start time in the
// target's temporary directory. Callers verify candidates with ProcessInfo2.
func findDiagnosticSockets(tempDir string, namespacePID, startTime uint64) ([]string, error) {
	if namespacePID == 0 {
		return nil, errors.New("diagnostic socket lookup requires a nonzero namespace PID")
	}
	directory, err := os.Open(tempDir)
	if err != nil {
		return nil, fmt.Errorf("opening diagnostic socket directory: %w", err)
	}
	defer directory.Close()

	// .NET names its default socket dotnet-diagnostic-{pid}-{disambiguation_key}-socket.
	// The PID is local to the runtime's PID namespace; the key is its process start time.
	// Match the full name here, then verify the candidate with ProcessInfo2.
	// https://learn.microsoft.com/dotnet/core/diagnostics/diagnostic-port#default-diagnostic-port
	expectedName := fmt.Sprintf("dotnet-diagnostic-%d-%d-socket", namespacePID, startTime)
	const directoryReadBatchSize = 128
	var sockets []string
	for {
		entries, err := directory.ReadDir(directoryReadBatchSize)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("reading diagnostic socket directory: %w", err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.Type()&os.ModeSocket == 0 || name != expectedName {
				continue
			}
			sockets = append(sockets, filepath.Join(tempDir, name))
		}
		if errors.Is(err, io.EOF) {
			return sockets, nil
		}
	}
}

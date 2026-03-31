// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

import (
	"path/filepath"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"
)

var sigusr1Quoted = []string{`"SIGUSR1"`, `'SIGUSR1'`, "`SIGUSR1`"}

// sourceHasSIGUSR1Reference scans the Node.js application's source files for
// references to "SIGUSR1", 'SIGUSR1', or `SIGUSR1`. This is a fallback
// detection method used when the symbol-based detection fails (e.g. stripped
// binaries with dynamic libuv).
func sourceHasSIGUSR1Reference(pid int) bool {
	dir, err := harvest.FindNodeJSAppDir(app.PID(pid))
	if err != nil {
		return false
	}

	return dirHasSIGUSR1Reference(dir)
}

func lineContainsSIGUSR1(line string) bool {
	for _, pattern := range sigusr1Quoted {
		if strings.Contains(line, pattern) {
			return true
		}
	}
	return false
}

func scanFileForSIGUSR1(path string) bool {
	found := false
	_ = harvest.ScanJSFileLines(path, func(line string) bool {
		if lineContainsSIGUSR1(line) {
			found = true
			return true
		}
		return false
	})
	return found
}

// dirHasSIGUSR1Reference scans JS/TS source files in the given directory for
// quoted SIGUSR1 references.
func dirHasSIGUSR1Reference(dir string) bool {
	found := false

	_ = harvest.WalkJSFiles(dir, func(path string) error {
		if scanFileForSIGUSR1(path) {
			found = true
			return filepath.SkipAll
		}
		return nil
	})

	return found
}

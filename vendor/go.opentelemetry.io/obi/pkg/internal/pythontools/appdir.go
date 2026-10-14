// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pythontools // import "go.opentelemetry.io/obi/pkg/internal/pythontools"

import (
	"fmt"
	"path/filepath"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/langtools"
	"go.opentelemetry.io/obi/pkg/internal/pythontools/frameworks"
)

// AppDirForPID returns the local application directory for a Python process.
func AppDirForPID(pid app.PID, env map[string]string) (string, error) {
	exe, args, err := cmdlineForPID(pid)
	if err != nil {
		return "", fmt.Errorf("read Python command line: %w", err)
	}
	cwd, err := cwdForPID(pid)
	if err != nil {
		return "", fmt.Errorf("read Python working directory: %w", err)
	}

	launch := parsePythonLaunch(exe, args, env)
	return appDir(rootDirForPID(pid), cwd, launch)
}

func appDir(root, cwd string, launch frameworks.PythonLaunch) (string, error) {
	dir := launch.AppDir
	if launch.ScriptDir != "" {
		dir = launch.ScriptDir
	}
	if launch.TargetKind == frameworks.TargetFile || launch.TargetKind == frameworks.TargetScriptPath {
		target := frameworks.TargetReference(launch.Target)
		if target != "" {
			dir = filepath.Dir(target)
		}
	}
	if dir == "" {
		dir = cwd
	}

	path, info, ok := langtools.StatProcessPath(root, cwd, dir)
	if !ok || !info.IsDir() {
		return "", fmt.Errorf("resolve Python application directory %q", dir)
	}
	return path, nil
}

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package langtools // import "go.opentelemetry.io/obi/pkg/internal/langtools"

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// StatProcessPath resolves a process path and returns its file information.
func StatProcessPath(root, cwd, path string) (string, fs.FileInfo, bool) {
	return resolveProcessPath(root, cwd, path, true)
}

func ResolveProcessPath(root, cwd, path string) (string, bool) {
	resolved, _, ok := resolveProcessPath(root, cwd, path, false)
	return resolved, ok
}

func resolveProcessPath(root, cwd, path string, withFileInfo bool) (string, fs.FileInfo, bool) {
	if root == "" || path == "" {
		return "", nil, false
	}

	var containerPath string
	if filepath.IsAbs(path) {
		containerPath = filepath.Clean(path)
	} else {
		containerPath = filepath.Clean(filepath.Join(cwd, path))
	}
	if !filepath.IsAbs(containerPath) {
		return "", nil, false
	}

	hostPath := filepath.Join(root, strings.TrimPrefix(containerPath, string(filepath.Separator)))
	if !pathInRoot(root, hostPath) {
		return "", nil, false
	}

	if procRootPath(root) {
		if pathHasSymlink(root, containerPath) {
			return "", nil, false
		}
		info, err := os.Stat(hostPath)
		if err != nil {
			return "", nil, false
		}
		return hostPath, info, true
	}

	rootEval, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", nil, false
	}
	hostEval, err := filepath.EvalSymlinks(hostPath)
	if err != nil {
		return "", nil, false
	}
	if !pathInRoot(rootEval, hostEval) {
		return "", nil, false
	}
	if !withFileInfo {
		return hostEval, nil, true
	}

	info, err := os.Stat(hostEval)
	if err != nil {
		return "", nil, false
	}
	return hostEval, info, true
}

var procRootPath = IsProcRoot

func pathHasSymlink(root, containerPath string) bool {
	parts := strings.Split(strings.TrimPrefix(containerPath, string(filepath.Separator)), string(filepath.Separator))
	path := root
	for _, part := range parts {
		if part == "" {
			continue
		}

		path = filepath.Join(path, part)
		info, err := os.Lstat(path)
		if err != nil {
			return false
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return true
		}
	}
	return false
}

func IsProcRoot(root string) bool {
	root = filepath.Clean(root)
	if !strings.HasPrefix(root, "/proc/") || !strings.HasSuffix(root, "/root") {
		return false
	}

	pid := strings.TrimSuffix(strings.TrimPrefix(root, "/proc/"), "/root")
	if pid == "" {
		return false
	}
	for _, r := range pid {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func pathInRoot(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

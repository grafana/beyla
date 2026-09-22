// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package phptools // import "go.opentelemetry.io/obi/pkg/internal/phptools"

import (
	"os"
	"path/filepath"

	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/langtools"
)

const (
	maxProjectSearchDepth       = 4
	maxProjectSearchDirectories = 512
)

var hostRoot = ebpfcommon.RootDirectoryForPID(1)

type ProjectMetadata struct {
	Root         string
	Name         string
	Version      string
	FallbackName string
}

func findProject(root, cwd string, args []string, isFPM bool) ProjectMetadata {
	boundary, ok := langtools.ResolveProcessPath(root, string(filepath.Separator), string(filepath.Separator))
	if !ok {
		return ProjectMetadata{}
	}

	if !isFPM {
		if script := phpScriptArgument(args); script != "" {
			if path, info, ok := langtools.StatProcessPath(root, cwd, script); ok && info.Mode().IsRegular() {
				if project, found := findParentProject(filepath.Dir(path), boundary); found {
					return project
				}
			}
		}
	}

	if start, info, ok := langtools.StatProcessPath(root, string(filepath.Separator), cwd); ok && info.IsDir() {
		if project, found := findParentProject(start, boundary); found {
			return project
		}
	}

	if isFPM && (!ebpfcommon.HasHostPidAccess() || processRootDiffersFromHost(root)) {
		if project, found := processRootScanCache.scan(root, boundary, scanProcessRoot); found {
			return project
		}
	}

	return ProjectMetadata{}
}

func findParentProject(start, boundary string) (ProjectMetadata, bool) {
	var project ProjectMetadata
	found := false
	_ = langtools.WalkParentDirectories(start, boundary, func(dir string) (bool, error) {
		candidate, ok := inspectProject(dir)
		if !ok {
			return false, nil
		}
		project = candidate
		found = true
		return true, nil
	})
	return project, found
}

func scanProcessRoot(root, boundary string) (ProjectMetadata, bool) {
	type searchDirectory struct {
		path  string
		depth int
	}

	queue := []searchDirectory{{path: boundary}}
	var project ProjectMetadata
	found := false
	visited := 0

	for len(queue) > 0 {
		if visited >= maxProjectSearchDirectories {
			return ProjectMetadata{}, false
		}

		dir := queue[0]
		queue = queue[1:]
		visited++

		path, ok := resolveSearchDirectory(root, boundary, dir.path)
		if !ok {
			continue
		}

		if candidate, ok := inspectProject(path); ok {
			if found {
				return ProjectMetadata{}, false
			}
			project = candidate
			found = true
		}

		if dir.depth >= maxProjectSearchDepth {
			continue
		}

		entries, err := os.ReadDir(path)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				continue
			}

			child := filepath.Join(path, entry.Name())
			if skipSearchDirectory(boundary, child) {
				continue
			}
			queue = append(queue, searchDirectory{path: child, depth: dir.depth + 1})
		}
	}

	return project, found
}

func resolveSearchDirectory(root, boundary, path string) (string, bool) {
	rel, err := filepath.Rel(boundary, path)
	if err != nil {
		return "", false
	}
	processPath := string(filepath.Separator)
	if rel != "." {
		processPath = filepath.Join(processPath, rel)
	}
	resolved, info, ok := langtools.StatProcessPath(root, string(filepath.Separator), processPath)
	return resolved, ok && info.IsDir()
}

func skipSearchDirectory(boundary, path string) bool {
	name := filepath.Base(path)
	if name == "vendor" || name == "node_modules" || name == ".git" {
		return true
	}

	rel, err := filepath.Rel(boundary, path)
	if err != nil {
		return true
	}
	rel = filepath.ToSlash(rel)
	switch rel {
	case "bin", "boot", "dev", "etc", "lib", "lib64", "proc", "run", "sbin", "sys", "tmp",
		"usr/bin", "usr/include", "usr/lib", "usr/lib64", "usr/sbin", "usr/share",
		"usr/local/bin", "usr/local/lib", "usr/local/lib64", "usr/local/sbin", "usr/local/share",
		"var/cache", "var/lib", "var/log", "var/run", "var/tmp":
		return true
	default:
		return false
	}
}

func processRootDiffersFromHost(root string) bool {
	processRoot, err := os.Stat(root)
	if err != nil {
		return false
	}
	obiRoot, err := os.Stat(hostRoot)
	return err == nil && !os.SameFile(processRoot, obiRoot)
}

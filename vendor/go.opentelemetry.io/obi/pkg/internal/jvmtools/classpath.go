// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package jvmtools // import "go.opentelemetry.io/obi/pkg/internal/jvmtools"

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const envClasspath = "CLASSPATH"

// JavaLaunch contains the application archive or classpath parsed from a Java command line.
type JavaLaunch struct {
	Jar       string
	Classpath string
}

// ScanRoot identifies an application archive or classes directory.
type ScanRoot struct {
	Path      string
	Directory bool
}

// ScanRoots resolves the application roots from a Java command line inside a process root.
func ScanRoots(root, cwd string, args []string, env map[string]string) ([]ScanRoot, error) {
	launch := ParseJavaLaunch(args, env)
	if launch.Jar != "" {
		path, ok := ResolveProcessPath(root, cwd, launch.Jar)
		if !ok {
			return nil, fmt.Errorf("invalid Java jar path %q", launch.Jar)
		}
		if !isRegularFile(path) {
			return nil, fmt.Errorf("java jar path %q is not a regular file", launch.Jar)
		}
		return []ScanRoot{{Path: path}}, nil
	}

	classpath := launch.Classpath
	if classpath == "" {
		classpath = cwd
	}
	return ScanRootsFromClasspath(root, cwd, classpath), nil
}

func ParseJavaLaunch(args []string, env map[string]string) JavaLaunch {
	var classpath string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-jar":
			if i+1 < len(args) {
				return JavaLaunch{Jar: args[i+1]}
			}
			return JavaLaunch{}
		case arg == "-cp" || arg == "-classpath" || arg == "--class-path":
			if i+1 < len(args) {
				classpath = args[i+1]
				i++
			}
		case strings.HasPrefix(arg, "--class-path="):
			classpath = strings.TrimPrefix(arg, "--class-path=")
		}
	}

	if classpath != "" {
		return JavaLaunch{Classpath: classpath}
	}

	if env != nil {
		return JavaLaunch{Classpath: env[envClasspath]}
	}
	return JavaLaunch{}
}

func classpathRoots(root, cwd string, launch JavaLaunch) []ScanRoot {
	if launch.Jar != "" {
		path, ok := ResolveProcessPath(root, cwd, launch.Jar)
		if ok && isRegularFile(path) {
			return []ScanRoot{{Path: path}}
		}
		return nil
	}

	classpath := launch.Classpath
	if classpath == "" {
		classpath = cwd
	}
	return ScanRootsFromClasspath(root, cwd, classpath)
}

func ScanRootsFromClasspath(root, cwd, classpath string) []ScanRoot {
	var roots []ScanRoot
	for _, entry := range filepath.SplitList(classpath) {
		if entry == "" {
			continue
		}

		if strings.Contains(entry, "*") {
			roots = append(roots, scanArchiveRootsFromWildcard(root, cwd, entry)...)
			continue
		}

		ScanRoot, ok := ScanRootFromClasspathEntry(root, cwd, entry)
		if !ok {
			continue
		}

		roots = append(roots, ScanRoot)
	}

	return roots
}

func ScanRootFromClasspathEntry(root, cwd, entry string) (ScanRoot, bool) {
	path, ok := ResolveProcessPath(root, cwd, entry)
	if !ok {
		return ScanRoot{}, false
	}

	info, err := os.Stat(path)
	if err != nil {
		return ScanRoot{}, false
	}
	if info.IsDir() {
		return ScanRoot{Path: path, Directory: true}, true
	}
	if info.Mode().IsRegular() && isJavaArchive(path) {
		return ScanRoot{Path: path}, true
	}
	return ScanRoot{}, false
}

func scanArchiveRootsFromWildcard(root, cwd, entry string) []ScanRoot {
	dirEntry, ok := classpathWildcardDir(entry)
	if !ok {
		return nil
	}

	dir, ok := ResolveProcessPath(root, cwd, dirEntry)
	if !ok {
		return nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var roots []ScanRoot
	for _, file := range entries {
		if file.IsDir() || !isJavaArchive(file.Name()) {
			continue
		}

		childEntry := filepath.Join(dirEntry, file.Name())
		ScanRoot, ok := ScanRootFromClasspathEntry(root, cwd, childEntry)
		if ok && !ScanRoot.Directory {
			roots = append(roots, ScanRoot)
		}
	}
	return roots
}

func classpathWildcardDir(entry string) (string, bool) {
	if filepath.Base(entry) != "*" {
		return "", false
	}

	dir := filepath.Dir(entry)
	if strings.Contains(dir, "*") {
		return "", false
	}
	return dir, true
}

func ResolveProcessPath(root, cwd, path string) (string, bool) {
	if root == "" || path == "" {
		return "", false
	}

	var containerPath string
	if filepath.IsAbs(path) {
		containerPath = filepath.Clean(path)
	} else {
		containerPath = filepath.Clean(filepath.Join(cwd, path))
	}
	if !filepath.IsAbs(containerPath) {
		return "", false
	}

	hostPath := filepath.Join(root, strings.TrimPrefix(containerPath, string(filepath.Separator)))
	if !pathInRoot(root, hostPath) {
		return "", false
	}

	if procRootPath(root) {
		if pathHasSymlink(root, containerPath) {
			return "", false
		}
		if _, err := os.Stat(hostPath); err != nil {
			return "", false
		}
		return hostPath, true
	}

	rootEval, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", false
	}
	hostEval, err := filepath.EvalSymlinks(hostPath)
	if err != nil {
		return "", false
	}
	if !pathInRoot(rootEval, hostEval) {
		return "", false
	}

	return hostEval, true
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

func isRegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func isJavaArchive(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".jar" || ext == ".war"
}

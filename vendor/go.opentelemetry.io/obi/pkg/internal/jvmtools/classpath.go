// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package jvmtools // import "go.opentelemetry.io/obi/pkg/internal/jvmtools"

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.opentelemetry.io/obi/pkg/internal/langtools"
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
	return scanRootsForLaunch(root, cwd, ParseJavaLaunch(args, env))
}

func scanRootsForLaunch(root, cwd string, launch JavaLaunch) ([]ScanRoot, error) {
	if launch.Jar != "" {
		path, info, ok := langtools.StatProcessPath(root, cwd, launch.Jar)
		if !ok {
			return nil, fmt.Errorf("invalid Java jar path %q", launch.Jar)
		}
		if !info.Mode().IsRegular() {
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
	roots, _ := scanRootsForLaunch(root, cwd, launch)
	return roots
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

		scanRoot, ok := ScanRootFromClasspathEntry(root, cwd, entry)
		if !ok {
			continue
		}

		roots = append(roots, scanRoot)
	}

	return roots
}

func ScanRootFromClasspathEntry(root, cwd, entry string) (ScanRoot, bool) {
	path, info, ok := langtools.StatProcessPath(root, cwd, entry)
	if !ok {
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

	dir, ok := langtools.ResolveProcessPath(root, cwd, dirEntry)
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
		scanRoot, ok := ScanRootFromClasspathEntry(root, cwd, childEntry)
		if ok && !scanRoot.Directory {
			roots = append(roots, scanRoot)
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

func isJavaArchive(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".jar" || ext == ".war"
}

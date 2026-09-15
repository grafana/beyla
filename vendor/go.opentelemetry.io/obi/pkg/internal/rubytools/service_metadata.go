// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rubytools // import "go.opentelemetry.io/obi/pkg/internal/rubytools"

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/langtools"
)

const (
	bundleGemfile = "BUNDLE_GEMFILE"
	gemHome       = "GEM_HOME"
	gemPath       = "GEM_PATH"
)

var (
	rootDirForPID = ebpfcommon.RootDirectoryForPID
	cmdlineForPID = ebpfcommon.CMDLineForPID
	cwdForPID     = ebpfcommon.CWDForPID
)

func ResolveServiceMetadata(fileInfo *exec.FileInfo) error {
	if fileInfo == nil {
		return errors.New("ruby service metadata requires process file info")
	}
	if fileInfo.ServiceAttrs().UID.Name != "" {
		return nil
	}

	name, found, err := discoverRailsServiceName(
		fileInfo.Pid(),
		fileInfo.ServiceAttrs().EnvVars,
	)
	if err != nil {
		return err
	}
	if found && langtools.ValidServiceName(name) {
		fileInfo.SetAutoServiceName(name)
	}
	return nil
}

func discoverRailsServiceName(
	pid app.PID,
	env map[string]string,
) (string, bool, error) {
	command, args, cmdlineErr := cmdlineForPID(pid)
	cwd, cwdErr := cwdForPID(pid)
	if err := errors.Join(cmdlineErr, cwdErr); err != nil {
		return "", false, err
	}
	root := rootDirForPID(pid)
	boundary, ok := langtools.ResolveProcessPath(root, "/", "/")
	if !ok {
		return "", false, errors.New("can't resolve process path")
	}

	launch := ParseRubyLaunch(command, args)
	return findRailsServiceName(root, boundary, cwd, launch, env)
}

func findRailsServiceName(
	root, boundary, cwd string,
	launch RubyLaunch,
	env map[string]string,
) (string, bool, error) {
	dependencyRoots := gemDependencyRoots(cwd, env)

	if launch.EntryPoint != "" && !pathInDependencyRoot(cwd, launch.EntryPoint, dependencyRoots) {
		if start, ok := searchStart(root, cwd, launch.EntryPoint, true); ok {
			name, found, err := findRailsProject(start, boundary)
			if err != nil || found {
				return name, found, err
			}
		}
	}

	if launch.ProjectPath != "" && !pathInDependencyRoot(cwd, launch.ProjectPath, dependencyRoots) {
		if start, ok := searchStart(
			root, cwd, launch.ProjectPath, projectPathLooksLikeFile(launch.ProjectPath),
		); ok {
			name, found, err := findRailsProject(start, boundary)
			if err != nil || found {
				return name, found, err
			}
		}
		if launch.projectPathAuthoritative {
			return "", false, nil
		}
	}

	if !pathInDependencyRoot("/", cwd, dependencyRoots) {
		if start, ok := langtools.ResolveProcessPath(root, "/", cwd); ok {
			name, found, err := findRailsProject(start, boundary)
			if err != nil || found {
				return name, found, err
			}
		}
	}

	if path := env[bundleGemfile]; path != "" && !pathInDependencyRoot(cwd, path, dependencyRoots) {
		if start, ok := searchStart(root, cwd, path, true); ok {
			return findRailsProject(start, boundary)
		}
	}

	return "", false, nil
}

func findRailsProject(start, boundary string) (string, bool, error) {
	var name string
	found := false
	err := langtools.WalkParentDirectories(start, boundary, func(dir string) (bool, error) {
		candidate, rails, err := inspectRailsProjectDirectory(dir)
		if err != nil {
			return true, err
		}

		if !rails {
			return false, nil
		}

		name = candidate
		if name == "" {
			name = serviceNameFromProjectDirectory(dir, boundary)
		}
		found = true
		return true, nil
	})
	return name, found, err
}

func inspectRailsProjectDirectory(dir string) (string, bool, error) {
	configPath := filepath.Join(dir, "config")
	configInfo, err := os.Lstat(configPath)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}

	if err != nil {
		return "", false, fmt.Errorf("checking Rails config directory %q: %w", configPath, err)
	}

	if configInfo.Mode()&os.ModeSymlink != 0 {
		return "", false, nil
	}

	if !configInfo.IsDir() {
		return "", false, nil
	}

	applicationPath := filepath.Join(configPath, "application.rb")
	applicationInfo, err := os.Lstat(applicationPath)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}

	if err != nil {
		return "", false, fmt.Errorf("checking Rails application file %q: %w", applicationPath, err)
	}

	if !applicationInfo.Mode().IsRegular() {
		return "", true, nil
	}

	return readRailsApplicationName(applicationPath), true, nil
}

func searchStart(root, cwd, path string, assumeFile bool) (string, bool) {
	if resolved, info, ok := langtools.StatProcessPath(root, cwd, path); ok {
		if info.IsDir() {
			return resolved, true
		}
		return projectDirectoryForFile(resolved), true
	}

	containerPath := langtools.AbsoluteProcessPath(cwd, path)
	if !assumeFile {
		return "", false
	}
	return langtools.ResolveProcessPath(root, "/", projectDirectoryForFile(containerPath))
}

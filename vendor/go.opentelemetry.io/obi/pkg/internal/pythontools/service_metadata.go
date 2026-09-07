// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pythontools // import "go.opentelemetry.io/obi/pkg/internal/pythontools"

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/langtools"
	"go.opentelemetry.io/obi/pkg/internal/pythontools/frameworks"
)

const (
	maxProjectFileBytes int64 = 2 * 1024 * 1024
	serviceVersion            = attr.Name("service.version")
)

var (
	rootDirForPID = ebpfcommon.RootDirectoryForPID
	cmdlineForPID = ebpfcommon.CMDLineForPID
	cwdForPID     = ebpfcommon.CWDForPID
)

type projectMetadata struct {
	name    string
	version string
}

type pyprojectData struct {
	metadata       projectMetadata
	entryPoint     string
	recognized     bool
	fastAPISection bool
}

func ResolveServiceMetadata(fileInfo *exec.FileInfo) error {
	if fileInfo == nil {
		return errors.New("python service metadata requires process file info")
	}

	service := fileInfo.ServiceAttrs()
	resolveName := service.UID.Name == ""
	resolveVersion := service.Metadata[serviceVersion] == ""
	if !resolveName && !resolveVersion {
		return nil
	}

	pid := fileInfo.Pid()
	executable, args, cmdlineErr := cmdlineForPID(pid)
	cwd, cwdErr := cwdForPID(pid)
	if err := errors.Join(cmdlineErr, cwdErr); err != nil {
		return err
	}

	root := rootDirForPID(pid)
	launch := parsePythonLaunch(executable, args, service.EnvVars)
	var resolutionErr error
	if launch.FastAPIAuto {
		var configDir string
		launch.Target, configDir, resolutionErr = findFastAPIEntryPoint(root, cwd)
		if launch.Target != "" {
			launch.TargetKind = frameworks.ClassifyTarget(launch.Target)
			launch.SearchPaths = append([]string{configDir}, launch.SearchPaths...)
		}
	}

	metadata := projectMetadata{}
	targetPath, resolvedTarget, targetFound := resolveTargetPath(root, cwd, launch, service.EnvVars)

	if launch.FlaskAuto {
		targetPath, resolvedTarget, targetFound = resolveFlaskTargetPath(root, cwd, launch, service.EnvVars)
	}

	if targetFound {
		launch.Target = resolvedTarget
		var err error
		metadata, err = findProjectMetadata(root, targetPath)
		resolutionErr = errors.Join(resolutionErr, err)
	} else if launch.TargetKind == frameworks.TargetDottedReference {
		launch.Target = ""
	}

	if resolveName {
		name := metadata.name
		if name == "" {
			name = frameworks.TargetName(launch.Target)
		}
		if name == "" {
			name = frameworks.CleanValue(launch.FallbackName)
		}
		if name != "" {
			fileInfo.SetAutoServiceName(name)
		}
	}

	if resolveVersion && metadata.version != "" {
		if service.Metadata == nil {
			service.Metadata = map[attr.Name]string{}
		}
		service.Metadata[serviceVersion] = metadata.version
		fileInfo.SetMetadata(service.Metadata)
	}

	return resolutionErr
}

func resolveFlaskTargetPath(root, cwd string, launch frameworks.PythonLaunch, env map[string]string) (string, string, bool) {
	for _, target := range []string{"wsgi", "app"} {
		launch.Target = target
		launch.TargetKind = frameworks.TargetModule
		launch.SearchPaths = []string{"."}
		if path, resolvedTarget, found := resolveTargetPath(root, cwd, launch, env); found {
			return path, resolvedTarget, true
		}
	}
	return "", "", false
}

type targetCandidate struct {
	path   string
	target string
}

type resolvedPythonModule struct {
	path        string
	searchPaths []string
	isPackage   bool
}

func resolveTargetPath(root, cwd string, launch frameworks.PythonLaunch, env map[string]string) (string, string, bool) {
	if launch.TargetKind == frameworks.TargetScriptPath {
		if launch.Target == "" {
			return "", "", false
		}
		return resolveTargetCandidates(root, []string{cwd}, []targetCandidate{
			{path: launch.Target, target: launch.Target},
			{path: filepath.Join(launch.Target, "__main__.py"), target: launch.Target},
		})
	}

	target := frameworks.TargetReference(launch.Target)
	if target == "" {
		return "", "", false
	}

	pathConfig := launch.PathConfig

	if !pathConfig.IgnorePythonEnvironment && env["PYTHONSAFEPATH"] != "" {
		pathConfig.SafePath = true
	}
	pythonPath := env["PYTHONPATH"]
	if pathConfig.IgnorePythonEnvironment {
		pythonPath = ""
	}
	includeCWD := !pathConfig.SafePath || launch.TargetKind == frameworks.TargetFile
	launcherPaths := launch.SearchPaths
	if launch.ScriptDir != "" {
		includeCWD = false
		if !pathConfig.SafePath {
			launcherPaths = append(slices.Clone(launcherPaths), launch.ScriptDir)
		}
	}
	roots := targetSearchRoots(cwd, launcherPaths, pythonPath, includeCWD)
	switch launch.TargetKind {
	case frameworks.TargetFile:
		candidates := []targetCandidate{{path: target, target: target}}
		if filepath.Ext(target) == "" {
			candidates = append(candidates,
				targetCandidate{path: target + ".py", target: target},
				targetCandidate{path: filepath.Join(target, "__init__.py"), target: target},
			)
		}
		return resolveTargetCandidates(root, roots, candidates)
	case frameworks.TargetModule:
		return resolveImportedModule(root, roots, target)
	case frameworks.TargetRunnableModule:
		return resolveRunnableModule(root, roots, target)
	case frameworks.TargetDottedReference:
		return resolveDottedReference(root, roots, target)
	default:
		return "", "", false
	}
}

func resolveTargetCandidates(root string, roots []string, candidates []targetCandidate) (string, string, bool) {
	for _, base := range roots {
		for _, candidate := range candidates {
			if path, ok := regularProcessFile(root, base, candidate.path); ok {
				return path, candidate.target, true
			}
		}
	}
	return "", "", false
}

func resolveImportedModule(root string, roots []string, module string) (string, string, bool) {
	resolved, found := resolvePythonModule(root, roots, module)
	if !found || resolved.path == "" {
		return "", "", false
	}
	return resolved.path, module, true
}

func resolveRunnableModule(root string, roots []string, module string) (string, string, bool) {
	resolved, found := resolvePythonModule(root, roots, module)
	if !found {
		return "", "", false
	}
	if !resolved.isPackage {
		return resolved.path, module, true
	}

	main, found := resolvePythonModuleParts(root, resolved.searchPaths, []string{"__main__"})
	if !found || main.isPackage || main.path == "" {
		return "", "", false
	}
	return main.path, module, true
}

func resolveDottedReference(root string, roots []string, target string) (string, string, bool) {
	parts := strings.Split(target, ".")
	for i := len(parts); i > 0; i-- {
		module := strings.Join(parts[:i], ".")
		resolved, found := resolvePythonModule(root, roots, module)
		if found && resolved.path != "" {
			return resolved.path, module, true
		}
	}
	return "", "", false
}

func resolvePythonModule(root string, roots []string, module string) (resolvedPythonModule, bool) {
	return resolvePythonModuleParts(root, roots, strings.Split(module, "."))
}

func resolvePythonModuleParts(root string, roots, parts []string) (resolvedPythonModule, bool) {
	searchPaths := roots
	for index, part := range parts {
		last := index == len(parts)-1
		var namespacePaths []string
		var packagePath string

		for _, base := range searchPaths {
			candidatePackage := filepath.Join(base, part)
			if path, ok := regularProcessFile(root, "/", filepath.Join(candidatePackage, "__init__.py")); ok {
				if last {
					return resolvedPythonModule{
						path:        path,
						searchPaths: []string{candidatePackage},
						isPackage:   true,
					}, true
				}
				packagePath = candidatePackage
				break
			}

			if path, ok := regularProcessFile(root, "/", filepath.Join(base, part+".py")); ok {
				if !last {
					return resolvedPythonModule{}, false
				}
				return resolvedPythonModule{path: path}, true
			}

			if processDirectory(root, candidatePackage) && !slices.Contains(namespacePaths, candidatePackage) {
				namespacePaths = append(namespacePaths, candidatePackage)
			}
		}

		if packagePath != "" {
			searchPaths = []string{packagePath}
			continue
		}
		if len(namespacePaths) == 0 {
			return resolvedPythonModule{}, false
		}
		if last {
			return resolvedPythonModule{searchPaths: namespacePaths, isPackage: true}, true
		}
		searchPaths = namespacePaths
	}
	return resolvedPythonModule{}, false
}

func regularProcessFile(root, base, path string) (string, bool) {
	resolved, info, ok := langtools.StatProcessPath(root, base, path)
	return resolved, ok && info.Mode().IsRegular()
}

func processDirectory(root, path string) bool {
	_, info, ok := langtools.StatProcessPath(root, "/", path)
	return ok && info.IsDir()
}

func targetSearchRoots(cwd string, launcherPaths []string, pythonPath string, includeCWD bool) []string {
	roots := make([]string, 0, len(launcherPaths)+2)
	for _, path := range launcherPaths {
		roots = appendProcessPath(roots, cwd, path)
	}
	if includeCWD {
		roots = appendProcessPath(roots, cwd, cwd)
	}
	for _, path := range filepath.SplitList(pythonPath) {
		if path == "" {
			path = cwd
		}
		roots = appendProcessPath(roots, cwd, path)
	}
	return roots
}

func appendProcessPath(paths []string, cwd, path string) []string {
	if path == "" {
		return paths
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(cwd, path)
	}
	path = filepath.Clean(path)
	if !slices.Contains(paths, path) {
		paths = append(paths, path)
	}
	return paths
}

func findProjectMetadata(root, targetPath string) (projectMetadata, error) {
	boundary, ok := langtools.ResolveProcessPath(root, "/", "/")
	if !ok {
		return projectMetadata{}, nil
	}

	var metadata projectMetadata
	err := langtools.WalkParentDirectories(filepath.Dir(targetPath), boundary, func(dir string) (bool, error) {
		pyproject, found, err := readPyproject(filepath.Join(dir, "pyproject.toml"))
		if err != nil {
			return false, err
		}
		pyprojectFound := found
		if found && pyproject.recognized {
			metadata = pyproject.metadata
			return true, nil
		}

		setup, found, err := readSetupConfig(filepath.Join(dir, "setup.cfg"))
		if err != nil {
			return false, err
		}
		if found && setup.recognized {
			metadata = setup.metadata
			return true, nil
		}
		return pyprojectFound || found, nil
	})
	return metadata, err
}

func findFastAPIEntryPoint(root, cwd string) (string, string, error) {
	boundary, ok := langtools.ResolveProcessPath(root, "/", "/")
	if !ok {
		return "", "", nil
	}
	dir, ok := langtools.ResolveProcessPath(root, "/", cwd)
	if !ok {
		return "", "", nil
	}

	var entryPoint string
	var configDir string
	err := langtools.WalkParentDirectories(dir, boundary, func(dir string) (bool, error) {
		pyproject, found, err := readPyproject(filepath.Join(dir, "pyproject.toml"))
		if err != nil {
			return false, err
		}
		pyprojectFound := found
		if found {
			if pyproject.entryPoint != "" {
				entryPoint = pyproject.entryPoint
				configDir = processPath(boundary, dir)
				return true, nil
			}
			if pyproject.recognized || pyproject.fastAPISection {
				return true, nil
			}
		}

		setup, found, err := readSetupConfig(filepath.Join(dir, "setup.cfg"))
		if err != nil {
			return false, err
		}
		if found && setup.recognized {
			return true, nil
		}
		return pyprojectFound || found, nil
	})
	return entryPoint, configDir, err
}

func processPath(root, hostPath string) string {
	rel, err := filepath.Rel(root, hostPath)
	if err != nil || rel == "." {
		return "/"
	}
	return string(filepath.Separator) + rel
}

func readPyproject(path string) (pyprojectData, bool, error) {
	data, found, err := readProjectFile(path)
	if err != nil || !found {
		return pyprojectData{}, found, err
	}

	var file struct {
		Project *struct {
			Name    string   `toml:"name"`
			Version string   `toml:"version"`
			Dynamic []string `toml:"dynamic"`
		} `toml:"project"`
		Tool struct {
			Poetry *struct {
				Name    string `toml:"name"`
				Version string `toml:"version"`
			} `toml:"poetry"`
			FastAPI *struct {
				EntryPoint string `toml:"entrypoint"`
			} `toml:"fastapi"`
		} `toml:"tool"`
	}
	if err := toml.Unmarshal(data, &file); err != nil {
		return pyprojectData{}, true, fmt.Errorf("parsing %s: %w", path, err)
	}

	result := pyprojectData{fastAPISection: file.Tool.FastAPI != nil}
	if file.Tool.FastAPI != nil {
		result.entryPoint = frameworks.CleanValue(file.Tool.FastAPI.EntryPoint)
	}
	if file.Project != nil {
		result.recognized = true
		result.metadata.name = cleanProjectName(file.Project.Name)
		if !slices.Contains(file.Project.Dynamic, "version") {
			result.metadata.version = frameworks.CleanValue(file.Project.Version)
		}
	} else if file.Tool.Poetry != nil {
		result.recognized = true
		result.metadata.name = cleanProjectName(file.Tool.Poetry.Name)
		result.metadata.version = frameworks.CleanValue(file.Tool.Poetry.Version)
	}
	return result, true, nil
}

func readSetupConfig(path string) (pyprojectData, bool, error) {
	data, found, err := readProjectFile(path)
	if err != nil || !found {
		return pyprojectData{}, found, err
	}

	result := pyprojectData{}
	section := ""
	for lineNumber, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return pyprojectData{}, true, fmt.Errorf("parsing %s:%d: malformed section", path, lineNumber+1)
			}
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if section == "metadata" {
				result.recognized = true
			}
			continue
		}
		if section != "metadata" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "name":
			result.metadata.name = cleanProjectName(value)
		case "version":
			value = strings.TrimSpace(value)
			lowerValue := strings.ToLower(value)
			if !strings.HasPrefix(lowerValue, "attr:") && !strings.HasPrefix(lowerValue, "file:") &&
				!strings.Contains(value, "%(") {
				result.metadata.version = frameworks.CleanValue(value)
			}
		}
	}
	return result, true, nil
}

func readProjectFile(path string) ([]byte, bool, error) {
	file, found := langtools.OpenMetadataFile(path, maxProjectFileBytes)
	if file == nil {
		return nil, found, nil
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxProjectFileBytes+1))
	if err != nil {
		return nil, true, err
	}
	if int64(len(data)) > maxProjectFileBytes {
		return nil, true, fmt.Errorf("project metadata file %s exceeds %d bytes", path, maxProjectFileBytes)
	}
	return data, true, nil
}

func cleanProjectName(value string) string {
	value = frameworks.CleanValue(value)
	for i := range len(value) {
		char := value[i]
		alphanumeric := char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9'
		if alphanumeric {
			continue
		}
		if i == 0 || i == len(value)-1 || char != '-' && char != '_' && char != '.' {
			return ""
		}
	}
	return value
}

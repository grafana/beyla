// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejstools // import "go.opentelemetry.io/obi/pkg/internal/nodejstools"

import (
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/langtools"
)

const (
	maxPackageJSONBytes int64 = 2 * 1024 * 1024
	npmPackageJSON            = "npm_package_json"
	serviceVersion            = attr.Name("service.version")
)

var nodeExtensionFallbacks = [...]string{".js", ".json", ".node"}

var (
	rootDirForPID = ebpfcommon.RootDirectoryForPID
	cmdlineForPID = ebpfcommon.CMDLineForPID
	cwdForPID     = ebpfcommon.CWDForPID
)

type packageMetadata struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Main    string `json:"main"`
	valid   bool
}

func ResolveServiceMetadata(fileInfo *exec.FileInfo) error {
	if fileInfo == nil {
		return errors.New("node.js service metadata requires process file info")
	}

	service := fileInfo.ServiceAttrs()
	resolveName := service.UID.Name == ""
	resolveVersion := service.Metadata[serviceVersion] == ""
	if !resolveName && !resolveVersion {
		return nil
	}

	pid := fileInfo.Pid()
	_, args, cmdlineErr := cmdlineForPID(pid)
	cwd, cwdErr := cwdForPID(pid)
	if err := errors.Join(cmdlineErr, cwdErr); err != nil {
		return err
	}

	root := rootDirForPID(pid)
	launch := ParseNodeLaunch(args)
	metadata := findPackageMetadata(root, cwd, launch.EntryPoint, service.EnvVars)
	if resolveName {
		name, namespace, ok := parsePackageName(metadata.Name)
		if ok {
			fileInfo.SetAutoServiceName(name)
			if namespace != "" && service.UID.Namespace == "" {
				fileInfo.SetAutoServiceNamespace(namespace)
			}
		} else if name := serviceNameFromEntryPoint(cwd, launch.EntryPoint); name != "" &&
			nodeEntryPointExists(root, cwd, launch.EntryPoint) {
			fileInfo.SetAutoServiceName(name)
		}
	}

	if resolveVersion {
		version := strings.TrimSpace(metadata.Version)
		if version != "" {
			if service.Metadata == nil {
				service.Metadata = map[attr.Name]string{}
			}
			service.Metadata[serviceVersion] = version
			fileInfo.SetMetadata(service.Metadata)
		}
	}

	return nil
}

func findPackageMetadata(root, cwd, entryPoint string, env map[string]string) packageMetadata {
	if path := env[npmPackageJSON]; path != "" && !pathHasNodeModules(cwd, path) {
		if resolved, ok := langtools.ResolveProcessPath(root, cwd, path); ok {
			if metadata, found := readPackageJSON(resolved); found {
				return metadata
			}
		}
	}

	start, ok := packageSearchStart(root, cwd, entryPoint)
	if !ok {
		return packageMetadata{}
	}
	boundary, ok := langtools.ResolveProcessPath(root, "/", "/")
	if !ok {
		return packageMetadata{}
	}

	var metadata packageMetadata
	_ = langtools.WalkParentDirectories(start, boundary, func(dir string) (bool, error) {
		foundMetadata, found := readPackageJSON(filepath.Join(dir, "package.json"))
		if found {
			metadata = foundMetadata
		}
		return found, nil
	})
	return metadata
}

func packageSearchStart(root, cwd, entryPoint string) (string, bool) {
	if entryPoint == "" || pathHasNodeModules(cwd, entryPoint) {
		return langtools.ResolveProcessPath(root, "/", cwd)
	}
	if path, ok := resolveNodeFile(root, cwd, entryPoint); ok {
		return filepath.Dir(path), true
	}

	path, info, ok := langtools.StatProcessPath(root, cwd, entryPoint)
	if ok {
		if info.IsDir() {
			return path, true
		}
		return filepath.Dir(path), true
	}

	entryPoint = absoluteProcessPath(cwd, entryPoint)
	return langtools.ResolveProcessPath(root, "/", filepath.Dir(entryPoint))
}

func readPackageJSON(path string) (packageMetadata, bool) {
	file, found := langtools.OpenMetadataFile(path, maxPackageJSONBytes)
	if file == nil {
		return packageMetadata{}, found
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxPackageJSONBytes+1))
	if err != nil || int64(len(data)) > maxPackageJSONBytes {
		return packageMetadata{}, true
	}

	var fields struct {
		Name    json.RawMessage `json:"name"`
		Version json.RawMessage `json:"version"`
		Main    json.RawMessage `json:"main"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return packageMetadata{}, true
	}

	metadata := packageMetadata{valid: true}
	_ = json.Unmarshal(fields.Name, &metadata.Name)
	_ = json.Unmarshal(fields.Version, &metadata.Version)
	_ = json.Unmarshal(fields.Main, &metadata.Main)
	return metadata, true
}

func parsePackageName(value string) (string, string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsFunc(value, unicode.IsControl) {
		return "", "", false
	}

	if !strings.HasPrefix(value, "@") {
		if strings.Contains(value, "/") {
			return "", "", false
		}
		return value, "", true
	}

	scope, name, ok := strings.Cut(strings.TrimPrefix(value, "@"), "/")
	if !ok || scope == "" || name == "" || strings.Contains(name, "/") {
		return "", "", false
	}
	return name, scope, true
}

func serviceNameFromEntryPoint(cwd, entryPoint string) string {
	if entryPoint == "" || pathHasNodeModules(cwd, entryPoint) {
		return ""
	}

	name := filepath.Base(entryPoint)
	name = strings.TrimSuffix(name, filepath.Ext(name))
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." || name == "-" ||
		name == string(filepath.Separator) || strings.ContainsFunc(name, unicode.IsControl) {
		return ""
	}
	return name
}

func nodeEntryPointExists(root, cwd, entryPoint string) bool {
	if _, ok := resolveNodeFile(root, cwd, entryPoint); ok {
		return true
	}

	directory, ok := processDirectory(root, cwd, entryPoint)
	if !ok {
		return false
	}
	metadata, found := readPackageJSON(filepath.Join(directory, "package.json"))
	if found && !metadata.valid {
		return false
	}
	if metadata.Main == "" {
		_, ok := resolveNodeExtensionFile(root, cwd, filepath.Join(entryPoint, "index"))
		return ok
	}
	main := metadata.Main
	if !filepath.IsAbs(main) {
		main = filepath.Join(entryPoint, main)
	}
	if _, ok := resolveNodeFile(root, cwd, main); ok {
		return true
	}
	if _, ok := resolveNodeExtensionFile(root, cwd, filepath.Join(main, "index")); ok {
		return true
	}
	_, ok = resolveNodeExtensionFile(root, cwd, filepath.Join(entryPoint, "index"))
	return ok
}

func resolveNodeFile(root, cwd, path string) (string, bool) {
	if resolved, ok := resolveRegularProcessFile(root, cwd, path); ok {
		return resolved, true
	}
	return resolveNodeExtensionFile(root, cwd, path)
}

func resolveNodeExtensionFile(root, cwd, path string) (string, bool) {
	for _, extension := range nodeExtensionFallbacks {
		if resolved, ok := resolveRegularProcessFile(root, cwd, path+extension); ok {
			return resolved, true
		}
	}
	return "", false
}

func processDirectory(root, cwd, path string) (string, bool) {
	resolved, info, ok := langtools.StatProcessPath(root, cwd, path)
	return resolved, ok && info.IsDir()
}

func resolveRegularProcessFile(root, cwd, path string) (string, bool) {
	resolved, info, ok := langtools.StatProcessPath(root, cwd, path)
	if !ok || !info.Mode().IsRegular() {
		return "", false
	}
	return resolved, true
}

func pathHasNodeModules(cwd, path string) bool {
	return slices.Contains(strings.Split(absoluteProcessPath(cwd, path), string(filepath.Separator)), "node_modules")
}

func absoluteProcessPath(cwd, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Clean(filepath.Join(cwd, path))
}

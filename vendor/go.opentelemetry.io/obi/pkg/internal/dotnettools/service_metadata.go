// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnettools // import "go.opentelemetry.io/obi/pkg/internal/dotnettools"

import (
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"unicode"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/langtools"
)

const (
	maxDepsJSONBytes int64 = 16 * 1024 * 1024
	serviceVersion         = attr.Name("service.version")
)

var (
	rootDirForPID = ebpfcommon.RootDirectoryForPID
	cmdlineForPID = ebpfcommon.CMDLineForPID
	cwdForPID     = ebpfcommon.CWDForPID
)

type serviceMetadata struct {
	Name    string
	Version string
}

type metadataSource struct {
	name     string
	depsFile string
	cwd      string
}

type depsDocument struct {
	RuntimeTarget struct {
		Name string `json:"name"`
	} `json:"runtimeTarget"`
	Targets   map[string]map[string]depsTarget `json:"targets"`
	Libraries map[string]depsLibrary           `json:"libraries"`
}

type depsTarget struct {
	Runtime map[string]json.RawMessage `json:"runtime"`
}

type depsLibrary struct {
	Type string `json:"type"`
}

func ResolveServiceMetadata(fileInfo *exec.FileInfo) error {
	if fileInfo == nil {
		return errors.New(".NET service metadata requires process file info")
	}

	service := fileInfo.ServiceAttrs()
	resolveName := service.UID.Name == ""
	resolveVersion := service.Metadata[serviceVersion] == ""
	if !resolveName && !resolveVersion {
		return nil
	}

	source, inspectionErr := metadataSourceForProcess(fileInfo)
	if source.name == "" {
		return inspectionErr
	}

	metadata := serviceMetadata{Name: source.name}
	if path, ok := langtools.ResolveProcessPath(
		rootDirForPID(fileInfo.Pid()), source.cwd, source.depsFile,
	); ok {
		if detected := readDepsJSON(path, source.name); detected.Name != "" {
			metadata = detected
		}
	}

	if name, ok := normalizeMetadataValue(metadata.Name); resolveName && ok {
		fileInfo.SetAutoServiceName(name)
	}
	if version, ok := normalizeMetadataValue(metadata.Version); resolveVersion && ok {
		if service.Metadata == nil {
			service.Metadata = map[attr.Name]string{}
		}
		service.Metadata[serviceVersion] = version
		fileInfo.SetMetadata(service.Metadata)
	}

	return inspectionErr
}

func metadataSourceForProcess(fileInfo *exec.FileInfo) (metadataSource, error) {
	executable := fileInfo.CmdExePath()
	if !isDotnetHost(fileInfo.ExecutableName()) {
		base := trimExecutableSuffix(executable)
		source := metadataSource{
			name:     filepath.Base(base),
			depsFile: base + ".deps.json",
		}
		if filepath.IsAbs(executable) {
			return source, nil
		}
		cwd, err := cwdForPID(fileInfo.Pid())
		source.cwd = cwd
		return source, err
	}

	_, args, err := cmdlineForPID(fileInfo.Pid())
	if err != nil {
		return metadataSource{}, err
	}

	launch := parseDotnetLaunch(args)
	if launch.EntryPoint == "" {
		return metadataSource{}, nil
	}

	extension := filepath.Ext(launch.EntryPoint)
	base := strings.TrimSuffix(launch.EntryPoint, extension)
	source := metadataSource{
		name:     filepath.Base(base),
		depsFile: base + ".deps.json",
	}
	if launch.DepsFile != "" {
		source.depsFile = launch.DepsFile
	}
	if filepath.IsAbs(launch.EntryPoint) && filepath.IsAbs(source.depsFile) {
		return source, nil
	}

	source.cwd, err = cwdForPID(fileInfo.Pid())
	return source, err
}

func readDepsJSON(path, entryAssembly string) serviceMetadata {
	file, ok := langtools.OpenMetadataFile(path, maxDepsJSONBytes)

	if file == nil || !ok {
		return serviceMetadata{}
	}

	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxDepsJSONBytes+1))
	if err != nil || int64(len(data)) > maxDepsJSONBytes {
		return serviceMetadata{}
	}

	var document depsDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return serviceMetadata{}
	}
	target, ok := document.Targets[document.RuntimeTarget.Name]
	if !ok {
		return serviceMetadata{}
	}

	wantedAsset := entryAssembly + ".dll"
	var metadata serviceMetadata
	matches := 0
	for libraryKey, library := range document.Libraries {
		name, version, ok := strings.Cut(libraryKey, "/")
		if !ok || name != entryAssembly || version == "" || library.Type != "project" {
			continue
		}
		entry, ok := target[libraryKey]
		if !ok || !containsRuntimeAsset(entry.Runtime, wantedAsset) {
			continue
		}

		metadata = serviceMetadata{Name: name, Version: version}
		matches++
	}
	if matches != 1 {
		return serviceMetadata{}
	}
	return metadata
}

func containsRuntimeAsset(runtime map[string]json.RawMessage, wanted string) bool {
	for asset := range runtime {
		if filepath.Base(filepath.FromSlash(asset)) == wanted {
			return true
		}
	}
	return false
}

func isDotnetHost(name string) bool {
	return strings.EqualFold(name, "dotnet") || strings.EqualFold(name, "dotnet.exe")
}

func trimExecutableSuffix(path string) string {
	if strings.EqualFold(filepath.Ext(path), ".exe") {
		return strings.TrimSuffix(path, filepath.Ext(path))
	}
	return path
}

func normalizeMetadataValue(value string) (string, bool) {
	value = strings.TrimSpace(value)
	return value, value != "" && value != "." && value != ".." && !strings.ContainsFunc(value, unicode.IsControl)
}

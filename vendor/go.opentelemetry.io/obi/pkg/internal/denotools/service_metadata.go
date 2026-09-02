// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package denotools // import "go.opentelemetry.io/obi/pkg/internal/denotools"

import (
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	pathpkg "path"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	"github.com/tidwall/jsonc"
	"golang.org/x/mod/semver"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/langtools"
)

const (
	maxServiceMetadataBytes int64 = 2 * 1024 * 1024
	denoNoPackageJSON             = "DENO_NO_PACKAGE_JSON"
	serviceVersion                = attr.Name("service.version")
)

var (
	rootDirForPID = ebpfcommon.RootDirectoryForPID
	cmdlineForPID = ebpfcommon.CMDLineForPID
	cwdForPID     = ebpfcommon.CWDForPID
)

type serviceMetadata struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func ResolveServiceMetadata(fileInfo *exec.FileInfo) error {
	if fileInfo == nil {
		return errors.New("deno service metadata requires process file info")
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

	launch := ParseDenoLaunch(args)
	if !launch.DiscoverProject {
		return nil
	}

	metadata, found := findServiceMetadata(
		rootDirForPID(pid), cwd, launch, service.EnvVars, resolveName,
	)
	if !found {
		return nil
	}

	if resolveName {
		name, namespace, ok := parseProjectName(metadata.Name)
		if ok {
			fileInfo.SetAutoServiceName(name)
			if namespace != "" && service.UID.Namespace == "" {
				fileInfo.SetAutoServiceNamespace(namespace)
			}
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

func findServiceMetadata(
	root, cwd string,
	launch DenoLaunch,
	env map[string]string,
	requireName bool,
) (serviceMetadata, bool) {
	_, packageJSONDisabled := env[denoNoPackageJSON]
	boundary, ok := langtools.ResolveProcessPath(root, "/", "/")
	if !ok {
		return serviceMetadata{}, false
	}
	entryPoint, kind := classifyEntryPoint(launch.EntryPoint)
	if launch.direct {
		if kind == entryPointUnsupported {
			return serviceMetadata{}, false
		}
		if kind == entryPointLocal {
			if _, ok := langtools.ResolveProcessPath(root, cwd, entryPoint); !ok {
				return serviceMetadata{}, false
			}
		}
	}

	if !launch.NoConfig && launch.ConfigPath != "" {
		if configPath, local := localSpecifierPath(launch.ConfigPath); local {
			if resolved, ok := langtools.ResolveProcessPath(root, cwd, configPath); ok {
				if config, regular := readRegularMetadataFile(resolved, true); regular {
					if metadata, found := findProjectMetadata(
						filepath.Dir(resolved), boundary, false, !packageJSONDisabled, &config, requireName,
					); found {
						return metadata, true
					}
				}
			}
		}
	}

	switch kind {
	case entryPointRegistry:
		metadata := metadataFromRegistrySpecifier(entryPoint)
		return metadata, metadataMatches(metadata, requireName)
	case entryPointHTTP:
		metadata := serviceMetadata{Name: nameFromHTTPURL(entryPoint)}
		return metadata, metadataMatches(metadata, requireName)
	case entryPointUnsupported:
		return serviceMetadata{}, false
	}

	start, fallbackName, ok := localProjectStart(root, cwd, entryPoint, launch.direct)
	if !ok {
		return serviceMetadata{}, false
	}

	allowDenoConfig := !launch.NoConfig && launch.ConfigPath == ""
	if metadata, found := findProjectMetadata(
		start, boundary, allowDenoConfig, !packageJSONDisabled, nil, requireName,
	); found {
		return metadata, true
	}

	if requireName && fallbackName != "" {
		return serviceMetadata{Name: fallbackName}, true
	}
	return serviceMetadata{}, false
}

type entryPointKind uint8

const (
	entryPointLocal entryPointKind = iota
	entryPointRegistry
	entryPointHTTP
	entryPointUnsupported
)

func classifyEntryPoint(entryPoint string) (string, entryPointKind) {
	if entryPoint == "" {
		return "", entryPointLocal
	}
	if strings.HasPrefix(entryPoint, "jsr:") || strings.HasPrefix(entryPoint, "npm:") {
		return entryPoint, entryPointRegistry
	}
	if strings.HasPrefix(entryPoint, "http:") || strings.HasPrefix(entryPoint, "https:") {
		return entryPoint, entryPointHTTP
	}
	if strings.HasPrefix(entryPoint, "file:") {
		path, ok := localSpecifierPath(entryPoint)
		if !ok {
			return "", entryPointUnsupported
		}
		return path, entryPointLocal
	}

	parsed, err := url.Parse(entryPoint)
	if err == nil && parsed.Scheme != "" {
		return "", entryPointUnsupported
	}
	return entryPoint, entryPointLocal
}

func localSpecifierPath(specifier string) (string, bool) {
	parsed, err := url.Parse(specifier)
	if err != nil {
		return "", false
	}
	if parsed.Scheme == "" {
		return specifier, true
	}
	if parsed.Scheme != "file" || (parsed.Host != "" && parsed.Host != "localhost") {
		return "", false
	}
	if !filepath.IsAbs(parsed.Path) {
		return "", false
	}
	return parsed.Path, true
}

func localProjectStart(root, cwd, entryPoint string, mustExist bool) (string, string, bool) {
	if entryPoint == "" || pathHasNodeModules(cwd, entryPoint) {
		start, ok := langtools.ResolveProcessPath(root, "/", projectSearchCWD(cwd))
		return start, "", ok
	}

	resolved, ok := langtools.ResolveProcessPath(root, cwd, entryPoint)
	if !ok {
		if mustExist {
			return "", "", false
		}
		start, cwdOK := langtools.ResolveProcessPath(root, "/", cwd)
		return start, "", cwdOK
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", "", false
	}
	if info.IsDir() {
		return resolved, "", true
	}
	return filepath.Dir(resolved), serviceNameFromEntryPoint(entryPoint), true
}

func findProjectMetadata(
	start, boundary string,
	allowDenoConfig, allowPackageJSON bool,
	firstConfig *serviceMetadata,
	requireName bool,
) (serviceMetadata, bool) {
	if !pathWithinBoundary(boundary, start) {
		return serviceMetadata{}, false
	}

	for dir := start; ; dir = filepath.Dir(dir) {
		var denoMetadata serviceMetadata
		var foundDenoMetadata bool
		if firstConfig != nil {
			denoMetadata = *firstConfig
			firstConfig = nil
		} else if allowDenoConfig {
			denoMetadata, foundDenoMetadata = readDenoMetadata(dir)
		}

		var packageMetadata serviceMetadata
		var foundMetadata bool
		if allowPackageJSON {
			packageMetadata, foundMetadata = readMetadataFile(filepath.Join(dir, "package.json"), false)
		}
		metadata := mergeProjectMetadata(denoMetadata, packageMetadata)
		if metadataMatches(metadata, requireName) {
			return metadata, true
		}

		// if we found metadata, but the name was set by external env var, and this
		// is the name carrying metadata, stop searching for version.
		if (foundMetadata || foundDenoMetadata) && !requireName {
			if _, _, ok := parseProjectName(metadata.Name); ok {
				return serviceMetadata{}, false
			}
		}

		if dir == boundary || filepath.Dir(dir) == dir {
			return serviceMetadata{}, false
		}
	}
}

func readDenoMetadata(dir string) (serviceMetadata, bool) {
	metadata, found := readMetadataFile(filepath.Join(dir, "deno.json"), true)
	if found {
		return metadata, found
	}
	return readMetadataFile(filepath.Join(dir, "deno.jsonc"), true)
}

func mergeProjectMetadata(denoMetadata, packageMetadata serviceMetadata) serviceMetadata {
	metadata := serviceMetadata{
		Name:    validProjectName(denoMetadata.Name),
		Version: strings.TrimSpace(denoMetadata.Version),
	}
	if metadata.Name == "" {
		metadata.Name = validProjectName(packageMetadata.Name)
	}
	if metadata.Version == "" {
		metadata.Version = strings.TrimSpace(packageMetadata.Version)
	}
	return metadata
}

func metadataMatches(metadata serviceMetadata, requireName bool) bool {
	if requireName {
		_, _, ok := parseProjectName(metadata.Name)
		return ok
	}
	return strings.TrimSpace(metadata.Version) != ""
}

func readMetadataFile(path string, jsonWithComments bool) (serviceMetadata, bool) {
	file, found := langtools.OpenMetadataFile(path, maxServiceMetadataBytes)
	if file == nil {
		return serviceMetadata{}, found
	}
	defer file.Close()
	return decodeMetadataFile(file, jsonWithComments), true
}

func readRegularMetadataFile(path string, jsonWithComments bool) (serviceMetadata, bool) {
	file, _ := langtools.OpenMetadataFile(path, maxServiceMetadataBytes)
	if file == nil {
		return serviceMetadata{}, false
	}
	defer file.Close()
	return decodeMetadataFile(file, jsonWithComments), true
}

func decodeMetadataFile(file io.Reader, jsonWithComments bool) serviceMetadata {
	data, err := io.ReadAll(io.LimitReader(file, maxServiceMetadataBytes+1))
	if err != nil || int64(len(data)) > maxServiceMetadataBytes {
		return serviceMetadata{}
	}
	if jsonWithComments {
		data = jsonc.ToJSON(data)
	}

	var fields struct {
		Name    json.RawMessage `json:"name"`
		Version json.RawMessage `json:"version"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return serviceMetadata{}
	}

	var metadata serviceMetadata
	_ = json.Unmarshal(fields.Name, &metadata.Name)
	_ = json.Unmarshal(fields.Version, &metadata.Version)
	return metadata
}

func metadataFromRegistrySpecifier(specifier string) serviceMetadata {
	_, rest, _ := strings.Cut(specifier, ":")
	rest = strings.SplitN(rest, "?", 2)[0]
	rest = strings.SplitN(rest, "#", 2)[0]
	if rest == "" {
		return serviceMetadata{}
	}

	var rawName, version string
	if strings.HasPrefix(rest, "@") {
		scopeEnd := strings.Index(rest, "/")
		if scopeEnd < 2 {
			return serviceMetadata{}
		}
		scope := rest[1:scopeEnd]
		packagePart, _, _ := strings.Cut(rest[scopeEnd+1:], "/")
		name, parsedVersion := splitPackageVersion(packagePart)
		rawName = "@" + scope + "/" + name
		version = parsedVersion
	} else {
		packagePart, _, _ := strings.Cut(rest, "/")
		rawName, version = splitPackageVersion(packagePart)
	}

	if validProjectName(rawName) == "" {
		return serviceMetadata{}
	}
	if version != "" && !isExactSemver(version) {
		version = ""
	}
	return serviceMetadata{Name: rawName, Version: version}
}

func isExactSemver(version string) bool {
	if !semver.IsValid("v" + version) {
		return false
	}
	core, _, _ := strings.Cut(version, "-")
	core, _, _ = strings.Cut(core, "+")
	return strings.Count(core, ".") == 2
}

func splitPackageVersion(value string) (string, string) {
	index := strings.LastIndex(value, "@")
	if index <= 0 {
		return value, ""
	}
	return value[:index], value[index+1:]
}

func nameFromHTTPURL(specifier string) string {
	parsed, err := url.Parse(specifier)
	if err != nil || parsed.Host == "" || parsed.Path == "" || strings.HasSuffix(parsed.Path, "/") {
		return ""
	}
	return serviceNameFromEntryPoint(pathpkg.Base(parsed.Path))
}

func validProjectName(value string) string {
	if _, _, ok := parseProjectName(value); ok {
		return strings.TrimSpace(value)
	}
	return ""
}

func parseProjectName(value string) (string, string, bool) {
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

func serviceNameFromEntryPoint(entryPoint string) string {
	name := filepath.Base(entryPoint)
	name = strings.TrimSuffix(name, filepath.Ext(name))
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." || name == "-" ||
		name == string(filepath.Separator) || strings.ContainsFunc(name, unicode.IsControl) {
		return ""
	}
	return name
}

func pathHasNodeModules(cwd, path string) bool {
	if !filepath.IsAbs(path) {
		path = filepath.Join(cwd, path)
	}
	return slices.Contains(strings.Split(filepath.Clean(path), string(filepath.Separator)), "node_modules")
}

func projectSearchCWD(cwd string) string {
	separator := string(filepath.Separator)
	clean := filepath.Clean(cwd)
	prefix := separator
	for part := range strings.SplitSeq(strings.TrimPrefix(clean, separator), separator) {
		if part == "node_modules" {
			return prefix
		}
		prefix = filepath.Join(prefix, part)
	}
	return clean
}

func pathWithinBoundary(boundary, path string) bool {
	relative, err := filepath.Rel(boundary, path)
	if err != nil {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

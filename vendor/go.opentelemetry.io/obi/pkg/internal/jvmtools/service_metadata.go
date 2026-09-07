// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package jvmtools // import "go.opentelemetry.io/obi/pkg/internal/jvmtools"

import (
	"archive/zip"
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"go.yaml.in/yaml/v3"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/langtools"
)

const (
	maxServiceArchiveBytes  int64 = 256 * 1024 * 1024
	maxServiceResourceBytes int64 = 2 * 1024 * 1024

	envSpringApplicationName = "SPRING_APPLICATION_NAME"
	springApplicationName    = "spring.application.name"
	serviceVersion           = attr.Name("service.version")
	maxPlaceholderExpansions = 32
)

var (
	rootDirForPID = ebpfcommon.RootDirectoryForPID
	cmdlineForPID = ebpfcommon.CMDLineForPID
	cwdForPID     = ebpfcommon.CWDForPID
)

// ServiceMetadata contains service resource attributes derived from a Java launch.
type ServiceMetadata struct {
	Name    string
	Version string
}

var springResourceNames = []string{
	"application.properties",
	"application.yml",
	"application.yaml",
	"bootstrap.properties",
	"bootstrap.yml",
	"bootstrap.yaml",
}

// ResolveServiceMetadata derives missing Java service metadata from Spring configuration,
// the application manifest, and the launch JAR name.
func ResolveServiceMetadata(fileInfo *exec.FileInfo) error {
	if fileInfo == nil {
		return errors.New("java service metadata requires process file info")
	}

	service := fileInfo.ServiceAttrs()
	resolveName := service.UID.Name == ""
	resolveVersion := service.Metadata[serviceVersion] == ""
	if !resolveName && !resolveVersion {
		return nil
	}

	pid := fileInfo.Pid()
	env := service.EnvVars
	root := rootDirForPID(pid)

	_, args, cmdlineErr := cmdlineForPID(pid)
	cwd, cwdErr := cwdForPID(pid)
	resolutionErr := errors.Join(cmdlineErr, cwdErr)

	if resolutionErr != nil {
		return resolutionErr
	}

	var name string
	if resolveName && cmdlineErr == nil {
		name = springNameFromProgramArgs(args, env)
		if name == "" {
			name = springNameFromSystemProperties(args, env)
		}
	}
	if resolveName && name == "" {
		name, _ = resolvePlaceholders(env[envSpringApplicationName], env)
	}

	launch := ParseJavaLaunch(args, env)
	var roots []ScanRoot
	var mainJarPath string
	if cmdlineErr == nil && cwdErr == nil {
		if resolveName && name == "" {
			name = springNameFromCurrentDirectory(root, cwd, env)
		}

		roots = classpathRoots(root, cwd, launch)
		if launch.Jar != "" && len(roots) != 0 {
			mainJarPath = roots[0].Path
		}
		if resolveName && name == "" {
			name = springNameFromClasspath(roots, env)
		}
	}

	manifest := ServiceMetadata{}
	if mainJarPath != "" && (resolveVersion || name == "") {
		manifest = manifestServiceMetadata(mainJarPath)
	}
	if resolveName && name == "" {
		name = manifest.Name
	}
	if resolveName && name == "" {
		name = serviceNameFromJar(launch.Jar)
	}
	if !resolveVersion {
		manifest.Version = ""
	}

	if resolveName && name != "" {
		fileInfo.SetAutoServiceName(name)
	}

	if resolveVersion && manifest.Version != "" {
		service.Metadata[serviceVersion] = manifest.Version
		fileInfo.SetMetadata(service.Metadata)
	}

	return nil
}

func springNameFromProgramArgs(args []string, env map[string]string) string {
	const prefix = "--" + springApplicationName + "="
	for _, arg := range args {
		if !strings.HasPrefix(arg, prefix) {
			continue
		}
		if name, ok := resolvePlaceholders(strings.TrimPrefix(arg, prefix), env); ok {
			return name
		}
	}
	return ""
}

func springNameFromSystemProperties(args []string, env map[string]string) string {
	const prefix = "-D" + springApplicationName + "="
	var value string
	for _, arg := range args {
		if after, ok := strings.CutPrefix(arg, prefix); ok {
			value = after
		}
	}
	name, _ := resolvePlaceholders(value, env)
	return name
}

func springNameFromCurrentDirectory(root, cwd string, env map[string]string) string {
	for _, name := range springResourceNames[:3] {
		path, ok := langtools.ResolveProcessPath(root, cwd, name)
		if !ok {
			continue
		}
		data, ok := readRegularFile(path)
		if !ok {
			continue
		}
		if serviceName := springNameFromResource(name, data, env); serviceName != "" {
			return serviceName
		}
	}
	return ""
}

func springNameFromClasspath(roots []ScanRoot, env map[string]string) string {
	for _, resourceName := range springResourceNames {
		for _, root := range roots {
			data, ok := readClasspathResource(root, resourceName)
			if !ok {
				continue
			}
			if name := springNameFromResource(resourceName, data, env); name != "" {
				return name
			}
		}
	}
	return ""
}

func springNameFromResource(name string, data []byte, env map[string]string) string {
	var value string
	if strings.HasSuffix(name, ".properties") {
		value = propertyValue(data, springApplicationName)
	} else {
		value = yamlSpringApplicationName(data)
	}
	resolved, _ := resolvePlaceholders(value, env)
	return resolved
}

func readClasspathResource(root ScanRoot, name string) ([]byte, bool) {
	if root.Directory {
		return readRegularFile(filepath.Join(root.Path, name))
	}
	return readArchiveResource(root.Path, name)
}

func readRegularFile(path string) ([]byte, bool) {
	info, err := os.Lstat(path)
	// We shouldn't have a symlink here, but we check to avoid escaping the root folder
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() > maxServiceResourceBytes {
		return nil, false
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxServiceResourceBytes+1))
	return data, err == nil && int64(len(data)) <= maxServiceResourceBytes
}

func readArchiveResource(path, name string) ([]byte, bool) {
	reader, ok := openArchive(path)
	if !ok {
		return nil, false
	}
	defer reader.Close()

	bootLayout := false
	var rootEntry *zip.File
	var bootEntry *zip.File
	for _, file := range reader.File {
		entryName := filepath.ToSlash(file.Name)
		if entryName == "BOOT-INF/classes/" || strings.HasPrefix(entryName, "BOOT-INF/classes/") {
			bootLayout = true
		}
		switch entryName {
		case name:
			rootEntry = file
		case "BOOT-INF/classes/" + name:
			bootEntry = file
		}
	}
	if bootLayout {
		return readZipEntry(bootEntry)
	}
	return readZipEntry(rootEntry)
}

func manifestServiceMetadata(path string) ServiceMetadata {
	reader, ok := openArchive(path)
	if !ok {
		return ServiceMetadata{}
	}
	defer reader.Close()

	for _, file := range reader.File {
		if filepath.ToSlash(file.Name) != "META-INF/MANIFEST.MF" {
			continue
		}
		data, ok := readZipEntry(file)
		if !ok {
			return ServiceMetadata{}
		}
		return parseManifest(data)
	}
	return ServiceMetadata{}
}

func openArchive(path string) (*zip.ReadCloser, bool) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxServiceArchiveBytes {
		return nil, false
	}
	reader, err := zip.OpenReader(path)
	return reader, err == nil
}

func readZipEntry(file *zip.File) ([]byte, bool) {
	if file == nil || file.UncompressedSize64 > uint64(maxServiceResourceBytes) {
		return nil, false
	}
	reader, err := file.Open()
	if err != nil {
		return nil, false
	}
	defer reader.Close()

	data, err := io.ReadAll(io.LimitReader(reader, maxServiceResourceBytes+1))
	return data, err == nil && int64(len(data)) <= maxServiceResourceBytes
}

func parseManifest(data []byte) ServiceMetadata {
	values := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 1024), int(maxServiceResourceBytes))
	var key string
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if line == "" {
			break
		}
		if strings.HasPrefix(line, " ") && key != "" {
			values[key] += strings.TrimPrefix(line, " ")
			continue
		}
		separator := strings.IndexByte(line, ':')
		if separator < 1 {
			key = ""
			continue
		}
		key = line[:separator]
		values[key] = strings.TrimPrefix(line[separator+1:], " ")
	}
	return ServiceMetadata{
		Name:    values["Implementation-Title"],
		Version: values["Implementation-Version"],
	}
}

func propertyValue(data []byte, wanted string) string {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 1024), int(maxServiceResourceBytes))
	var logical string
	var value string
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if logical != "" {
			line = strings.TrimLeftFunc(line, unicode.IsSpace)
		}
		logical += line
		if trailingBackslashes(logical)%2 == 1 {
			logical = strings.TrimSuffix(logical, "\\")
			continue
		}
		key, candidate, ok := splitProperty(logical)
		logical = ""
		if ok && unescapeProperty(key) == wanted {
			value = unescapeProperty(candidate)
		}
	}
	return value
}

func splitProperty(line string) (string, string, bool) {
	line = strings.TrimLeftFunc(line, unicode.IsSpace)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
		return "", "", false
	}

	escaped := false
	separator := len(line)
	for i, r := range line {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == '=' || r == ':' || unicode.IsSpace(r) {
			separator = i
			break
		}
	}

	key := line[:separator]
	remaining := strings.TrimLeftFunc(line[separator:], unicode.IsSpace)
	if strings.HasPrefix(remaining, "=") || strings.HasPrefix(remaining, ":") {
		remaining = strings.TrimLeftFunc(remaining[1:], unicode.IsSpace)
	}
	return key, remaining, key != ""
}

func trailingBackslashes(value string) int {
	count := 0
	for i := len(value) - 1; i >= 0 && value[i] == '\\'; i-- {
		count++
	}
	return count
}

func unescapeProperty(value string) string {
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] != '\\' || i+1 >= len(value) {
			out.WriteByte(value[i])
			continue
		}
		i++
		switch value[i] {
		case 't':
			out.WriteByte('\t')
		case 'n':
			out.WriteByte('\n')
		case 'r':
			out.WriteByte('\r')
		case 'f':
			out.WriteByte('\f')
		case 'u':
			if i+4 < len(value) {
				if decoded, err := strconv.ParseUint(value[i+1:i+5], 16, 16); err == nil {
					out.WriteRune(rune(decoded))
					i += 4
					continue
				}
			}
			out.WriteByte('u')
		default:
			out.WriteByte(value[i])
		}
	}
	return out.String()
}

func yamlSpringApplicationName(data []byte) string {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var document map[string]any
		err := decoder.Decode(&document)
		if errors.Is(err, io.EOF) {
			return ""
		}
		if err != nil {
			return ""
		}
		spring, ok := document["spring"].(map[string]any)
		if !ok {
			continue
		}
		application, ok := spring["application"].(map[string]any)
		if !ok {
			continue
		}
		if name, ok := application["name"].(string); ok {
			return name
		}
	}
}

func resolvePlaceholders(value string, env map[string]string) (string, bool) {
	if value == "" {
		return "", false
	}

	for range maxPlaceholderExpansions {
		start := strings.Index(value, "${")
		if start == -1 {
			return value, value != ""
		}

		if len(value) <= start+2 {
			return "", false
		}

		endOffset := strings.IndexByte(value[start+2:], '}')
		if endOffset == -1 {
			return "", false
		}

		end := start + 2 + endOffset
		expression := value[start+2 : end]
		key, fallback, hasFallback := strings.Cut(expression, ":")
		replacement, ok := lookupSpringEnvironment(env, key)
		if !ok {
			if !hasFallback {
				return "", false
			}
			replacement = fallback
		}
		value = value[:start] + replacement + value[end+1:]
	}
	return "", false
}

func springEnvVarName(key string) string {
	var sb strings.Builder
	for _, r := range key {
		switch r {
		case '.':
			sb.WriteByte('_')
		case '-':
		default:
			sb.WriteRune(unicode.ToUpper(r))
		}
	}

	return sb.String()
}

func lookupSpringEnvironment(env map[string]string, key string) (string, bool) {
	if value, ok := env[key]; ok {
		return value, true
	}

	envName := springEnvVarName(key)

	value, ok := env[envName]
	return value, ok
}

func serviceNameFromJar(path string) string {
	name := filepath.Base(path)
	if dot := strings.LastIndexByte(name, '.'); dot >= 0 {
		name = name[:dot]
	}
	return name
}

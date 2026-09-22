// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package phptools // import "go.opentelemetry.io/obi/pkg/internal/phptools"

import (
	"errors"
	"path/filepath"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/langtools"
)

const (
	appNameEnv     = "APP_NAME"
	serviceVersion = attr.Name("service.version")
)

var (
	rootDirForPID = ebpfcommon.RootDirectoryForPID
	cmdlineForPID = ebpfcommon.CMDLineForPID
	cwdForPID     = ebpfcommon.CWDForPID
)

// ResolveServiceMetadata derives missing PHP service metadata from Composer or
// APP_NAME (typically set for Laravel)
func ResolveServiceMetadata(fileInfo *exec.FileInfo) error {
	if fileInfo == nil {
		return errors.New("PHP service metadata requires process file info")
	}

	service := fileInfo.ServiceAttrs()
	resolveName := service.UID.Name == ""
	resolveVersion := service.Metadata[serviceVersion] == ""
	if !resolveName && !resolveVersion {
		return nil
	}

	project, projectErr := ProjectForPID(fileInfo)
	if resolveName {
		if name, ok := composerName(project.Name); ok {
			fileInfo.SetAutoServiceName(name)
		} else if name, ok := inferredName(service.EnvVars[appNameEnv]); ok {
			fileInfo.SetAutoServiceName(name)
		} else if project.Root != "" {
			name, ok := inferredName(readDotEnvAppName(filepath.Join(project.Root, ".env")))
			if !ok {
				name, ok = inferredName(project.FallbackName)
			}
			if ok {
				fileInfo.SetAutoServiceName(name)
			}
		}
	}

	if resolveVersion {
		if version, ok := composerVersion(project.Version); ok {
			if service.Metadata == nil {
				service.Metadata = map[attr.Name]string{}
			}
			service.Metadata[serviceVersion] = version
			fileInfo.SetMetadata(service.Metadata)
		}
	}

	return projectErr
}

func inferredName(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if !langtools.ValidServiceName(value) {
		return "", false
	}
	return value, true
}

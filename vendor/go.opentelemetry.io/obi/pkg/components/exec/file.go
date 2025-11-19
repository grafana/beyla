// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package goexec provides the utilities to analyze the executable code
package exec

import (
	"debug/elf"
	"fmt"
	"os"
	"strings"
	"syscall"

	"go.opentelemetry.io/obi/pkg/components/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/services"
)

type FileInfo struct {
	Service svc.Attrs

	CmdExePath     string
	ProExeLinkPath string
	ELF            *elf.File
	Pid            int32
	Ppid           int32
	Ino            uint64
	Ns             uint32
}

const (
	envServiceName      = "OTEL_SERVICE_NAME"
	envResourceAttrs    = "OTEL_RESOURCE_ATTRIBUTES"
	serviceNameKey      = "service.name"
	serviceNamespaceKey = "service.namespace"
)

func (fi *FileInfo) ExecutableName() string {
	parts := strings.Split(fi.CmdExePath, "/")
	return parts[len(parts)-1]
}

func FindExecELF(p *services.ProcessInfo, svcID svc.Attrs, k8sEnabled bool) (*FileInfo, error) {
	// In container environments or K8s, we can't just open the executable exe path, because it might
	// be in the volume of another pod/container. We need to access it through the /proc/<pid>/exe symbolic link
	ns, err := FindNamespace(p.Pid)
	if err != nil {
		return nil, fmt.Errorf("can't find namespace for PID=%d: %w", p.Pid, err)
	}
	file := FileInfo{
		Service:    svcID,
		CmdExePath: p.ExePath,
		// TODO: allow overriding /proc root folder
		ProExeLinkPath: fmt.Sprintf("/proc/%d/exe", p.Pid),
		Pid:            p.Pid,
		Ppid:           p.PPid,
		Ns:             ns,
	}
	if file.ELF, err = elf.Open(file.ProExeLinkPath); err != nil {
		return nil, fmt.Errorf("can't open ELF file in %s: %w", file.ProExeLinkPath, err)
	}

	info, err := os.Stat(file.ProExeLinkPath)
	if err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil, fmt.Errorf("couldn't cast stat into syscall.Stat_t for %s", file.ProExeLinkPath)
		}
		file.Ino = stat.Ino
	} else {
		return nil, err
	}

	envVars, err := EnvVars(p.Pid)
	if err != nil {
		return nil, err
	}

	file.Service = setServiceEnvVariables(file.Service, envVars, k8sEnabled)

	return &file, nil
}

func setServiceEnvVariables(service svc.Attrs, envVars map[string]string, k8sEnabled bool) svc.Attrs {
	service.EnvVars = envVars
	allVars := map[string]string{}
	service.Metadata = map[attr.Name]string{}
	if resourceAttrs, ok := service.EnvVars[envResourceAttrs]; ok {
		collect := func(k string, v string) {
			allVars[k] = v
		}
		attributes.ParseOTELResourceVariable(resourceAttrs, collect)

		for k, v := range allVars {
			if k != serviceNameKey && k != serviceNamespaceKey {
				service.Metadata[attr.Name(k)] = v
			}
		}
	}

	// If Kubernetes is enabled we use the K8S metadata as the source of truth
	// including the k8s supplied environment variables
	if k8sEnabled {
		return service
	}

	if svcName, ok := service.EnvVars[envServiceName]; ok {
		service.UID.Name = svcName
	} else if result, ok := allVars[serviceNameKey]; ok {
		service.UID.Name = result
	}

	if result, ok := allVars[serviceNamespaceKey]; ok {
		service.UID.Namespace = result
	}

	return service
}

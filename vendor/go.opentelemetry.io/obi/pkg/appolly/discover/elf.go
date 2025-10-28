// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"debug/elf"
	"fmt"
	"os"
	"syscall"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

const (
	envServiceName      = "OTEL_SERVICE_NAME"
	envResourceAttrs    = "OTEL_RESOURCE_ATTRIBUTES"
	serviceNameKey      = "service.name"
	serviceNamespaceKey = "service.namespace"
)

func findExecElf(p *services.ProcessInfo, svcID svc.Attrs, k8sEnabled bool) (*exec.FileInfo, error) {
	// In container environments or K8s, we can't just open the executable exe path, because it might
	// be in the volume of another pod/container. We need to access it through the /proc/<pid>/exe symbolic link
	ns, err := procs.FindNamespace(p.Pid)
	if err != nil {
		return nil, fmt.Errorf("can't find namespace for PID=%d: %w", p.Pid, err)
	}
	file := exec.FileInfo{
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

	envVars, err := procs.EnvVars(p.Pid)
	if err != nil {
		return nil, err
	}

	file.Service = setServiceEnvVariables(file.Service, envVars, k8sEnabled)

	return &file, nil
}

func setServiceEnvVariables(service svc.Attrs, envVars map[string]string, k8sEnabled bool) svc.Attrs {
	service.EnvVars = envVars
	// If Kubernetes is enabled we use the K8S metadata as the source of truth
	// including the k8s supplied environment variables
	if k8sEnabled {
		return service
	}
	if svcName, ok := service.EnvVars[envServiceName]; ok {
		service.UID.Name = svcName
	} else {
		if resourceAttrs, ok := service.EnvVars[envResourceAttrs]; ok {
			allVars := map[string]string{}
			collect := func(k string, v string) {
				allVars[k] = v
			}
			attributes.ParseOTELResourceVariable(resourceAttrs, collect)
			if result, ok := allVars[serviceNameKey]; ok {
				service.UID.Name = result
			} else if result, ok := allVars[serviceNamespaceKey]; ok {
				service.UID.Namespace = result
			}
		}
	}

	return service
}

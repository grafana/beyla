// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"debug/elf"
	"fmt"
	"os"
	"strings"
	"syscall"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

const (
	envServiceName      = "OTEL_SERVICE_NAME"
	envResourceAttrs    = "OTEL_RESOURCE_ATTRIBUTES"
	serviceNameKey      = "service.name"
	serviceNamespaceKey = "service.namespace"
)

func findExecElf(p *services.ProcessInfo, svcID svc.Attrs) (*exec.FileInfo, error) {
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

	file.Service = setServiceEnvVariables(file.Service, envVars)

	return &file, nil
}

func setServiceEnvVariables(service svc.Attrs, envVars map[string]string) svc.Attrs {
	service.EnvVars = envVars
	m := map[attr.Name]string{}
	allVars := map[string]string{}

	// We pull out the metadata from the OTEL resource variables. This is better than taking them from
	// Kubernetes, because the variables will be fully resolved when they are passed to the process.

	// Parse all resource attributes provided to the process and add them to the metadata
	if resourceAttrs, ok := service.EnvVars[envResourceAttrs]; ok {
		collect := func(k string, v string) {
			allVars[k] = v
		}
		attributes.ParseOTELResourceVariable(resourceAttrs, collect)

		for k, v := range allVars {
			// ignore empty or unresolved variables
			if v != "" && !strings.HasPrefix(v, "$") {
				m[attr.Name(k)] = v
			}
		}
	}

	// thread safe map update
	service.Metadata = m

	// Set the service name and namespace, if we found non-empty, resolved names, in the OTEL variables.
	// 1. For service name, first consider OTEL_SERVICE_NAME, then look for service.name in OTEL_RESOURCE_ATTRIBUTES
	// 2. For service namespace, look in OTEL_RESOURCE_ATTRIBUTES
	if svcName := service.EnvVars[envServiceName]; svcName != "" && !strings.HasPrefix(svcName, "$") {
		service.UID.Name = svcName
	} else if svcName := allVars[serviceNameKey]; svcName != "" && !strings.HasPrefix(svcName, "$") {
		service.UID.Name = svcName
	}

	if svcNamespace := allVars[serviceNamespaceKey]; svcNamespace != "" && !strings.HasPrefix(svcNamespace, "$") {
		service.UID.Namespace = svcNamespace
	}

	return service
}

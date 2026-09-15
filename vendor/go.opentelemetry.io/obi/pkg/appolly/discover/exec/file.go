// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package exec provides the utilities to analyze the executable code
package exec // import "go.opentelemetry.io/obi/pkg/appolly/discover/exec"

import (
	"debug/elf"
	"maps"
	"strings"
	"sync"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	appruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/transform/route"
)

const (
	envServiceName      = "OTEL_SERVICE_NAME"
	envResourceAttrs    = "OTEL_RESOURCE_ATTRIBUTES"
	serviceNameKey      = "service.name"
	serviceNamespaceKey = "service.namespace"
)

type Init struct {
	Service        svc.Attrs
	CmdExePath     string
	ProExeLinkPath string
	ELF            *elf.File
	Pid            app.PID
	Ppid           app.PID
	StartTime      uint64
	Dev            uint64
	Ino            uint64
	Ns             uint32
}

type FileInfo struct {
	mu          sync.RWMutex
	service     svc.Attrs
	runtimeGen  map[app.PID]uint64
	pythonFinal map[app.PID]appruntime.PythonRuntimeMetricFinal

	runtimeMetricServiceSource *FileInfo

	cmdExePath     string
	proExeLinkPath string
	elfFile        *elf.File
	pid            app.PID
	ppid           app.PID
	startTime      uint64
	dev            uint64
	ino            uint64
	ns             uint32
}

func New(init Init) *FileInfo {
	return &FileInfo{
		service:        init.Service,
		runtimeGen:     map[app.PID]uint64{},
		pythonFinal:    map[app.PID]appruntime.PythonRuntimeMetricFinal{},
		cmdExePath:     init.CmdExePath,
		proExeLinkPath: init.ProExeLinkPath,
		elfFile:        init.ELF,
		pid:            init.Pid,
		ppid:           init.Ppid,
		startTime:      init.StartTime,
		dev:            init.Dev,
		ino:            init.Ino,
		ns:             init.Ns,
	}
}

// SetPythonRuntimeMetricFinal stages one PID's termination data on the service FileInfo.
// The process event drains it before exporters remove the PID baseline.
func (fi *FileInfo) SetPythonRuntimeMetricFinal(value appruntime.PythonRuntimeMetricFinal) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	if fi.pythonFinal == nil {
		fi.pythonFinal = map[app.PID]appruntime.PythonRuntimeMetricFinal{}
	}
	fi.pythonFinal[value.PID] = value
}

// TakePythonRuntimeMetricFinal drains one PID's staged Python termination data.
func (fi *FileInfo) TakePythonRuntimeMetricFinal(pid app.PID) (appruntime.PythonRuntimeMetricFinal, bool) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	value, ok := fi.pythonFinal[pid]
	delete(fi.pythonFinal, pid)
	return value, ok
}

func (fi *FileInfo) RuntimeMetricGeneration(pid app.PID) uint64 {
	fi.mu.RLock()
	defer fi.mu.RUnlock()

	return fi.runtimeGen[pid]
}

func (fi *FileInfo) SetRuntimeMetricGeneration(pid app.PID, generation uint64) {
	fi.mu.Lock()
	defer fi.mu.Unlock()

	if fi.runtimeGen == nil {
		fi.runtimeGen = map[app.PID]uint64{}
	}
	fi.runtimeGen[pid] = generation
}

func (fi *FileInfo) SetRuntimeMetricServiceSource(source *FileInfo) {
	fi.mu.Lock()
	defer fi.mu.Unlock()

	fi.runtimeMetricServiceSource = source
}

func (fi *FileInfo) RuntimeMetricServiceSource() *FileInfo {
	fi.mu.RLock()
	defer fi.mu.RUnlock()

	return fi.runtimeMetricServiceSource
}

// Identity getters. Fields are set at construction and never mutated, so
// no locking is required.

func (fi *FileInfo) Pid() app.PID           { return fi.pid }
func (fi *FileInfo) Ppid() app.PID          { return fi.ppid }
func (fi *FileInfo) StartTime() uint64      { return fi.startTime }
func (fi *FileInfo) Dev() uint64            { return fi.dev }
func (fi *FileInfo) Ino() uint64            { return fi.ino }
func (fi *FileInfo) Ns() uint32             { return fi.ns }
func (fi *FileInfo) CmdExePath() string     { return fi.cmdExePath }
func (fi *FileInfo) ProExeLinkPath() string { return fi.proExeLinkPath }
func (fi *FileInfo) ELF() *elf.File         { return fi.elfFile }

func (fi *FileInfo) ExecutableName() string {
	parts := strings.Split(fi.cmdExePath, "/")
	return parts[len(parts)-1]
}

func (fi *FileInfo) ServiceAttrs() svc.Attrs {
	fi.mu.RLock()
	defer fi.mu.RUnlock()

	out := fi.service
	out.Metadata = maps.Clone(fi.service.Metadata)
	out.EnvVars = maps.Clone(fi.service.EnvVars)

	// no need to clone the other fields as they are immutable
	return out
}

// UnsafeServiceAttrs should be used only when dealing with span events
func (fi *FileInfo) UnsafeServiceAttrs() svc.Attrs {
	fi.mu.RLock()
	defer fi.mu.RUnlock()
	return fi.service
}

func (fi *FileInfo) SDKLanguage() svc.InstrumentableType {
	fi.mu.RLock()
	defer fi.mu.RUnlock()
	return fi.service.SDKLanguage
}

func (fi *FileInfo) ExportsOTelMetrics() bool {
	fi.mu.RLock()
	defer fi.mu.RUnlock()
	return fi.service.ExportsOTelMetrics()
}

func (fi *FileInfo) ExportsOTelTraces() bool {
	fi.mu.RLock()
	defer fi.mu.RUnlock()
	return fi.service.ExportsOTelTraces()
}

func (fi *FileInfo) ExportsOTelMetricsSpan() bool {
	fi.mu.RLock()
	defer fi.mu.RUnlock()
	return fi.service.ExportsOTelMetricsSpan()
}

func (fi *FileInfo) LogEnricherEnabled() bool {
	fi.mu.RLock()
	defer fi.mu.RUnlock()
	return fi.service.LogEnricherEnabled
}

func (fi *FileInfo) SetSDKLanguage(t svc.InstrumentableType) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	fi.service.SDKLanguage = t
}

func (fi *FileInfo) SetHarvestedRoutes(m route.Matcher) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	fi.service.HarvestedRouteMatcher = m
}

func (fi *FileInfo) SetMetadata(m map[attr.Name]string) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	fi.service.Metadata = m
}

func (fi *FileInfo) SetHostNameInstance(hostName, instance string) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	fi.service.HostName = hostName
	fi.service.UID.Instance = instance
}

func (fi *FileInfo) SetHostName(h string) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	fi.service.HostName = h
}

// SetExplicitServiceName sets a name that was explicitly configured (not
// auto-derived), clearing any prior auto-name flag so later auto-name
// propagation (e.g. k8s decoration) does not silently override it.
func (fi *FileInfo) SetExplicitServiceName(name string) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	fi.service.UID.Name = name
	fi.service.ClearAutoName()
}

func (fi *FileInfo) SetAutoServiceName(name string) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	fi.service.UID.Name = name
	fi.service.SetAutoName()
}

func (fi *FileInfo) SetAutoServiceNamespace(namespace string) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	fi.service.UID.Namespace = namespace
	fi.service.SetAutoNamespace()
}

func (fi *FileInfo) SetUID(uid svc.UID) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	fi.service.UID = uid
}

func (fi *FileInfo) AutoName() bool {
	fi.mu.RLock()
	defer fi.mu.RUnlock()
	return fi.service.AutoName()
}

// ApplyServiceDefaults sets an auto-derived service name (when none is set)
// and the SDK language. Intended for use during discovery, before *FileInfo
// is shared downstream.
func (fi *FileInfo) ApplyServiceDefaults(t svc.InstrumentableType) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	if fi.service.UID.Name == "" {
		fi.service.UID.Name = fi.ExecutableName()
		fi.service.SetAutoName()
	}
	fi.service.SDKLanguage = t
}

// ApplyEnvVariables parses the process environment and updates the service
// attributes (EnvVars, Metadata, UID name/namespace) from OTEL_SERVICE_NAME
// and OTEL_RESOURCE_ATTRIBUTES. Intended for use during discovery.
func (fi *FileInfo) ApplyEnvVariables(envVars map[string]string) {
	fi.mu.Lock()
	defer fi.mu.Unlock()

	fi.service.EnvVars = envVars
	m := maps.Clone(fi.service.Metadata)
	if m == nil {
		m = map[attr.Name]string{}
	}
	allVars := map[string]string{}

	if resourceAttrs, ok := fi.service.EnvVars[envResourceAttrs]; ok {
		attributes.ParseOTELResourceVariable(resourceAttrs, func(k, v string) { allVars[k] = v })
		for k, v := range allVars {
			if v != "" && !strings.HasPrefix(v, "$") {
				key := attr.Name(k)
				if _, exists := m[key]; !exists {
					m[key] = v
				}
			}
		}
	}
	fi.service.Metadata = m

	if svcName := fi.service.EnvVars[envServiceName]; svcName != "" && !strings.HasPrefix(svcName, "$") {
		fi.service.UID.Name = svcName
	} else if svcName := allVars[serviceNameKey]; svcName != "" && !strings.HasPrefix(svcName, "$") {
		fi.service.UID.Name = svcName
	}

	if svcNamespace := allVars[serviceNamespaceKey]; svcNamespace != "" && !strings.HasPrefix(svcNamespace, "$") {
		fi.service.UID.Namespace = svcNamespace
	}
}

// EnsureExportsOTelMetrics returns true if this call flipped the flag.
func (fi *FileInfo) EnsureExportsOTelMetrics() bool {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	if fi.service.ExportsOTelMetrics() {
		return false
	}
	fi.service.SetExportsOTelMetrics()
	return true
}

func (fi *FileInfo) EnsureExportsOTelTraces() bool {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	if fi.service.ExportsOTelTraces() {
		return false
	}
	fi.service.SetExportsOTelTraces()
	return true
}

func (fi *FileInfo) EnsureExportsOTelMetricsSpan() bool {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	if fi.service.ExportsOTelMetricsSpan() {
		return false
	}
	fi.service.SetExportsOTelMetricsSpan()
	return true
}

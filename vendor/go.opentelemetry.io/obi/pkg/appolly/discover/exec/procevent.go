// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package exec // import "go.opentelemetry.io/obi/pkg/appolly/discover/exec"

import appruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"

type ProcessEventType int

const (
	ProcessEventCreated = ProcessEventType(iota)
	ProcessEventTerminated
)

type ProcessEvent struct {
	File                      *FileInfo
	Type                      ProcessEventType
	FinalPythonRuntimeMetrics []appruntime.PythonRuntimeMetricFinal
}

func (pe ProcessEvent) ServiceFile() *FileInfo {
	if pe.File == nil {
		return nil
	}
	if source := pe.File.RuntimeMetricServiceSource(); source != nil {
		return source
	}
	return pe.File
}

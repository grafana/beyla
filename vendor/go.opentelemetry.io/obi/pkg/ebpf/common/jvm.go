// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	jvmruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
)

func DecorateJVMRuntimeEvent(filter ServiceFilter, event *jvmruntime.JVMRuntimeEvent) bool {
	if filter == nil {
		return false
	}
	pids := filter.CurrentPIDs(PIDTypeKProbes)
	namespacePIDs, ok := pids[event.PIDNamespaceID]
	if !ok {
		return false
	}
	if service, ok := namespacePIDs[event.PID]; ok {
		event.Service = service
		return true
	}
	return false
}

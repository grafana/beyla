// Package attr contains definition of the attribute names of for the metrics, especially
// for the metrics whose reported attributes are selected in the attributes.select YAML option
package names

import (
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"
	semconv2 "go.opentelemetry.io/otel/semconv/v1.25.0"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// Process Metrics following OTEL 1.26 experimental conventions
// https://opentelemetry.io/docs/specs/semconv/resource/process/
// https://opentelemetry.io/docs/specs/semconv/system/process-metrics/
const (
	ProcCommand     = attr.Name(semconv.ProcessCommandKey)
	ProcCommandLine = attr.Name(semconv.ProcessCommandLineKey)
	ProcCPUMode     = attr.Name("cpu.mode")
	ProcDiskIODir   = attr.Name(semconv2.DiskIoDirectionKey)
	ProcNetIODir    = attr.Name(semconv2.NetworkIoDirectionKey)
	ProcOwner       = attr.Name(semconv.ProcessOwnerKey)
	ProcParentPid   = attr.Name(semconv.ProcessParentPIDKey)
	ProcPid         = attr.Name(semconv.ProcessPIDKey)
	ProcCommandArgs = attr.Name(semconv.ProcessCommandArgsKey)
	ProcExecName    = attr.Name(semconv.ProcessExecutableNameKey)
	ProcExecPath    = attr.Name(semconv.ProcessExecutablePathKey)
)

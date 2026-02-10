// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"
import "go.opentelemetry.io/obi/pkg/appolly/app"

func KernelVersion() (major, minor int) {
	return 0, 0
}

func hasCapSysAdmin() bool {
	return false
}

func HasHostPidAccess() bool {
	return true
}

func HasHostNetworkAccess() (bool, error) {
	return false, nil
}

func FindNetworkNamespace(_ app.PID) (string, error) {
	return "", nil
}

func RootDirectoryForPID(_ app.PID) string {
	return ""
}

func CMDLineForPID(_ app.PID) (string, []string, error) {
	return "", nil, nil
}

func CWDForPID(_ app.PID) (string, error) {
	return "", nil
}

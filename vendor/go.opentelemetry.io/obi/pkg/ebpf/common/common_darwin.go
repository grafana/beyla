// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

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

func FindNetworkNamespace(_ int32) (string, error) {
	return "", nil
}

func RootDirectoryForPID(_ int32) string {
	return ""
}

func CMDLineForPID(_ int32) (string, []string, error) {
	return "", nil, nil
}

func CWDForPID(_ int32) (string, error) {
	return "", nil
}

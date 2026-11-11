// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"
import "go.opentelemetry.io/obi/pkg/appolly/app"

func KernelVersion() (major, minor int) {
	return 0, 0
}

// HasAttachCookie / HasUprobeRefCtrOffset are linux-only kernel feature
// probes. Stubbed to false on darwin so the integration test package
// compiles for `go vet` and `go test -short` runs on dev macs.
func HasAttachCookie() bool {
	return false
}

func HasUprobeRefCtrOffset() bool {
	return false
}

func hasCapSysAdmin() bool {
	return false
}

func HasHostPidAccess() bool {
	return true
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

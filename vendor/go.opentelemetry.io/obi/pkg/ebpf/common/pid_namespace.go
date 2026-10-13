// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

// procPIDInitIno is PROC_PID_INIT_INO (include/linux/proc_ns.h), the inode of
// the initial pid namespace on every kernel.
const procPIDInitIno = 0xEFFFFFFC

// PIDNamespaceMode tells valid_pid() (bpf/pid/pid.h) how to number the current
// task the way OBI's /proc numbers it.
type PIDNamespaceMode uint32

const (
	// OBI's /proc is the initial pid namespace: the key is the host tgid.
	PIDNamespaceInit = PIDNamespaceMode(BpfPidNamespaceModeK_pidNsModeInit)
	// OBI's /proc is another pid namespace, a sidecar's pod or a node that is
	// itself a container: the key is the tgid in that namespace, for tasks in
	// it and in the namespaces below it.
	PIDNamespacePod = PIDNamespaceMode(BpfPidNamespaceModeK_pidNsModePod)
)

func pidNamespaceMode(ino uint64) PIDNamespaceMode {
	if ino == procPIDInitIno {
		return PIDNamespaceInit
	}

	return PIDNamespacePod
}

func pidFilterConstants(mode PIDNamespaceMode, ino uint64) map[string]any {
	return map[string]any{
		"pid_ns_mode":    uint32(mode),
		"obi_pid_ns_ino": ino,
	}
}

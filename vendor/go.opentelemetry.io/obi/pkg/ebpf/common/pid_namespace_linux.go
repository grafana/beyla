// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"log/slog"
	"os"
	"sync"
	"syscall"
)

// Pid 1 of a pid namespace always lives in it, so /proc/1 names the namespace
// OBI's /proc numbers processes in, even when that procfs is not the one of
// OBI's own pid namespace.
var procPIDNamespaceIno = sync.OnceValues(func() (uint64, error) {
	info, err := os.Stat("/proc/1/ns/pid")
	if err != nil {
		return 0, err
	}

	return info.Sys().(*syscall.Stat_t).Ino, nil
})

func PIDFilterConstants() map[string]any {
	log := slog.With("component", "ebpf.PIDFilter")

	ino, err := procPIDNamespaceIno()
	if err != nil {
		log.Warn("can't read the pid namespace of /proc, assuming the initial one", "error", err)
		return pidFilterConstants(PIDNamespaceInit, 0)
	}

	mode := pidNamespaceMode(ino)
	log.Debug("BPF PID filter namespace", "mode", mode, "ino", ino)

	return pidFilterConstants(mode, ino)
}

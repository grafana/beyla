// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/ebpf"

import (
	"errors"
	"log/slog"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	v2 "github.com/containers/common/pkg/cgroupv2"
	"golang.org/x/sys/unix"
)

const (
	cgroupFSRoot   = "/sys/fs/cgroup"
	cgroupV2Hybrid = "/sys/fs/cgroup/unified"
	cgroup2Magic   = 0x63677270
)

var errNoCgroupV2 = errors.New("no cgroupv2 hierarchy found")

// cgroupV2Result holds either a path (tier 1/2) or an mfd (tier 3 anonymous
// mount). The mfd is kept open for the process lifetime by sync.OnceValue.
type cgroupV2Result struct {
	path string
	mfd  int
	err  error
}

var cgroupV2Once = sync.OnceValue(func() cgroupV2Result {
	log := slog.With("component", "ebpf.cgroupv2")
	if enabled, err := v2.Enabled(); err == nil && enabled {
		return cgroupV2Result{path: cgroupFSRoot, mfd: -1}
	}
	if isCgroup2Mount(cgroupV2Hybrid) {
		return cgroupV2Result{path: cgroupV2Hybrid, mfd: -1}
	}
	mfd, err := fsmountCgroupV2()
	if err != nil {
		log.Warn("could not self-mount cgroupv2", "error", err)
		return cgroupV2Result{mfd: -1, err: errNoCgroupV2}
	}
	log.Info("self-mounted cgroup2 hierarchy via fsmount", "mfd", mfd)
	return cgroupV2Result{mfd: mfd}
})

func isCgroup2Mount(path string) bool {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return false
	}
	return st.Type == cgroup2Magic
}

// fsmountCgroupV2 creates an anonymous cgroupv2 mount via fsopen+fsmount.
// The returned fd must stay open for the lifetime of any BPF link attached
// to it. Works on read-only filesystems; leaves no entry in /proc/mounts.
func fsmountCgroupV2() (int, error) {
	fsfd, err := unix.Fsopen("cgroup2", unix.FSOPEN_CLOEXEC)
	if err != nil {
		return -1, err
	}
	defer unix.Close(fsfd)
	if err := unix.FsconfigCreate(fsfd); err != nil {
		return -1, err
	}
	return unix.Fsmount(fsfd, unix.FSMOUNT_CLOEXEC, 0)
}

// AttachCgroupSockOps attaches a sockops program to the cgroupv2 hierarchy,
// hiding the path-vs-fd distinction between tier 1/2 and tier 3.
func AttachCgroupSockOps(prog *ebpf.Program, attach ebpf.AttachType) (link.Link, error) {
	r := cgroupV2Once()
	if r.err != nil {
		return nil, r.err
	}
	if r.path != "" {
		return link.AttachCgroup(link.CgroupOptions{
			Path:    r.path,
			Program: prog,
			Attach:  attach,
		})
	}
	return link.AttachRawLink(link.RawLinkOptions{
		Target:  r.mfd,
		Program: prog,
		Attach:  attach,
	})
}

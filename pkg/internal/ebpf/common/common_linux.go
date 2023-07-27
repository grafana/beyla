package ebpfcommon

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func (f *Filter) Close() error {
	return syscall.SetsockoptInt(f.Fd, unix.SOL_SOCKET, unix.SO_DETACH_BPF, 0)
}

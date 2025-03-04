package ebpfcommon

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/grafana/beyla/v2/pkg/internal/helpers"
)

func (f *Filter) Close() error {
	return syscall.SetsockoptInt(f.Fd, unix.SOL_SOCKET, unix.SO_DETACH_BPF, 0)
}

func (s *SockMsg) Close() error {
	return link.RawDetachProgram(link.RawDetachProgramOptions{
		Target:  s.MapFD,
		Program: s.Program,
		Attach:  s.AttachAs,
	})
}

func (s *SockOps) Close() error {
	return s.SockopsCgroup.Close()
}

// Copied from https://github.com/golang/go/blob/go1.21.3/src/internal/syscall/unix/kernel_version_linux.go
func KernelVersion() (major, minor int) {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return
	}

	var (
		values    [2]int
		value, vi int
	)
	for _, c := range uname.Release {
		if '0' <= c && c <= '9' {
			value = (value * 10) + int(c-'0')
		} else {
			// Note that we're assuming N.N.N here.
			// If we see anything else, we are likely to mis-parse it.
			values[vi] = value
			vi++
			if vi >= len(values) {
				break
			}
			value = 0
		}
	}

	return values[0], values[1]
}

func hasCapSysAdmin() bool {
	caps, err := helpers.GetCurrentProcCapabilities()
	return err == nil && caps.Has(unix.CAP_SYS_ADMIN)
}

func HasHostPidAccess() bool {
	return os.Getpid() != 1
}

func FindNetworkNamespace(pid int32) (string, error) {
	netPath := fmt.Sprintf("/proc/%d/ns/net", pid)
	f, err := os.Open(netPath)

	if err != nil {
		return "", fmt.Errorf("failed to open(/proc/%d/ns/net): %w", pid, err)
	}

	defer f.Close()

	// read the value of the symbolic link
	buf := make([]byte, syscall.PathMax)
	n, err := syscall.Readlink(netPath, buf)
	if err != nil {
		return "", fmt.Errorf("failed to read symlink(/proc/%d/ns/net): %w", pid, err)
	}

	return string(buf[:n]), nil
}

func HasHostNetworkAccess() (bool, error) {
	// Get the network namespace of the current process
	containerNS, err := FindNetworkNamespace(int32(os.Getpid()))
	if err != nil {
		return false, err
	}

	// Get the network namespace of the host process (PID 1)
	hostNS, err := FindNetworkNamespace(1)
	if err != nil {
		return false, err
	}

	// Compare the network namespaces
	return containerNS == hostNS, nil
}

func RootDirectoryForPID(pid int32) string {
	return filepath.Join("/proc", strconv.Itoa(int(pid)), "root")
}

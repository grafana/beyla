// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/internal/helpers"
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

// KernelVersion from https://github.com/golang/go/blob/go1.21.3/src/internal/syscall/unix/kernel_version_linux.go
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
	// not itself pid 1 and not running in sidecar mode
	// with pid:service
	return os.Getpid() != 1 && os.Getppid() != 0
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

// CMDLineForPID parses /proc/<pid>/cmdline and extracts the executable and arguments.
// Returns the executable path and a slice of arguments (excluding the executable).
// The cmdline file contains null-separated arguments.
func CMDLineForPID(pid int32) (string, []string, error) {
	cmdlinePath := filepath.Join("/proc", strconv.Itoa(int(pid)), "cmdline")
	exec, args, err := cmdLineForPath(cmdlinePath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read /proc/%d/cmdline: %w", pid, err)
	}
	return exec, args, nil
}

func cmdLineForPath(cmdlinePath string) (string, []string, error) {
	data, err := os.ReadFile(cmdlinePath)
	if err != nil {
		return "", nil, err
	}

	if len(data) == 0 {
		return "", nil, errors.New("empty cmd line")
	}

	// Parse null-separated arguments
	var components []string
	start := 0
	for i, b := range data {
		if b == 0 {
			if i > start {
				components = append(components, string(data[start:i]))
			}
			start = i + 1
		}
	}

	// Handle case where last argument doesn't end with null
	if start < len(data) {
		components = append(components, string(data[start:]))
	}

	if len(components) == 0 {
		return "", nil, errors.New("no command found")
	}

	executable := components[0]
	args := []string{}
	if len(components) > 1 {
		args = components[1:]
	}

	return executable, args, nil
}

// CWDForPID extracts the current working directory for a process by reading
// the symlink at /proc/<pid>/cwd.
func CWDForPID(pid int32) (string, error) {
	cwdPath := filepath.Join("/proc", strconv.Itoa(int(pid)), "cwd")

	cwd, err := os.Readlink(cwdPath)
	if err != nil {
		return "", fmt.Errorf("failed to read symlink /proc/%d/cwd: %w", pid, err)
	}

	return cwd, nil
}

type KSym string

const (
	KSymPipeWrite     KSym = "pipe_write"
	KSymAnonPipeWrite KSym = "anon_pipe_write"

	// Stable symbol, used for testing
	KSymTCPSendmsg KSym = "tcp_sendmsg"
	// Non-existent symbol, used for testing
	KSymTestDummy KSym = "test_dummy"
)

var kSymsCache = struct {
	sync.Once
	syms map[KSym]bool
	err  error
}{
	syms: map[KSym]bool{
		KSymPipeWrite:     false,
		KSymAnonPipeWrite: false,
		KSymTCPSendmsg:    false,
		KSymTestDummy:     false,
	},
}

func KernelHasSymbol(sym KSym) (bool, error) {
	kSymsCache.Do(func() {
		spec, err := btf.LoadKernelSpec()
		if err != nil {
			kSymsCache.err = fmt.Errorf("failed to load kernel BTF spec: %w", err)
			return
		}

		for s := range kSymsCache.syms {
			var function *btf.Func
			if err := spec.TypeByName(string(s), &function); err != nil {
				kSymsCache.syms[s] = false
				continue
			}
			kSymsCache.syms[s] = true
		}
	})

	if kSymsCache.err != nil {
		return false, kSymsCache.err
	}

	found, ok := kSymsCache.syms[sym]
	if !ok {
		return false, fmt.Errorf("symbol %q not in cache", sym)
	}

	return found, nil
}

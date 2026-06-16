// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package util // import "go.opentelemetry.io/obi/pkg/internal/jvmtools/util"

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Constants
const MaxPath = 4096

// GetTmpPath returns the target JVM temporary directory path.
func GetTmpPath(pid int) string {
	var tmpPath string
	// Try user-provided alternative path first
	vmTmpPath := os.Getenv("JVM_TMP_PATH")
	if vmTmpPath != "" && len(vmTmpPath) < MaxPath-100 {
		return vmTmpPath
	}

	if getTmpPathR(pid, &tmpPath) != nil {
		tmpPath = "/tmp"
	}

	return tmpPath
}

func getTmpPathR(pid int, buf *string) error {
	*buf = fmt.Sprintf("/proc/%d/root/tmp", pid)

	// Check if the remote /tmp can be accessed via /proc/[pid]/root
	_, err := os.Stat(*buf)
	return err
}

func GetProcessInfo(pid int, uid *int, gid *int, nspid *int) error {
	// Parse /proc/pid/status to find process credentials
	path := fmt.Sprintf("/proc/%d/status", pid)
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	nspidFound := false

	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "Uid:"):
			fields := strings.Fields(line[4:])
			if len(fields) > 1 {
				*uid = int(parseUint32(fields[1]))
			}
		case strings.HasPrefix(line, "Gid:"):
			fields := strings.Fields(line[4:])
			if len(fields) > 1 {
				*gid = int(parseUint32(fields[1]))
			}
		case strings.HasPrefix(line, "NStgid:"):
			fields := strings.Fields(line[7:])
			if len(fields) > 0 {
				*nspid = parseInt(fields[len(fields)-1])
				nspidFound = true
			}
		}
	}

	if !nspidFound {
		*nspid = altLookupNspid(pid)
	}

	return scanner.Err()
}

func parseUint32(s string) uint32 {
	val, _ := strconv.ParseUint(s, 10, 32)
	return uint32(val)
}

func parseInt(s string) int {
	val, _ := strconv.Atoi(s)
	return val
}

func altLookupNspid(pid int) int {
	path := fmt.Sprintf("/proc/%d/ns/pid", pid)

	// Don't bother looking for container PID if we are already in the same PID namespace
	oldnsStat, _ := os.Stat("/proc/self/ns/pid")
	newnsStat, _ := os.Stat(path)
	if os.SameFile(oldnsStat, newnsStat) {
		return pid
	}

	// Otherwise browse all PIDs in the namespace of the target process
	// trying to find which one corresponds to the host PID
	path = fmt.Sprintf("/proc/%d/root/proc", pid)
	dir, err := os.Open(path)
	if err != nil {
		return pid
	}
	defer dir.Close()

	entries, err := dir.Readdirnames(0)
	if err != nil {
		return pid
	}

	for _, entry := range entries {
		if len(entry) > 0 && entry[0] >= '1' && entry[0] <= '9' {
			// Check if /proc/<container-pid>/sched points back to <host-pid>
			schedPath := fmt.Sprintf("/proc/%d/root/proc/%s/sched", pid, entry)
			if schedGetHostPid(schedPath) == pid {
				pid, _ = strconv.Atoi(entry)
				break
			}
		}
	}

	return pid
}

func schedGetHostPid(path string) int {
	file, err := os.Open(path)
	if err != nil {
		return -1
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		line := scanner.Text()
		if c := strings.LastIndex(line, "("); c != -1 {
			return parseInt(line[c+1:])
		}
	}

	return -1
}

func namespaceFlag(nsType string) (int, bool) {
	switch nsType {
	case "net":
		return unix.CLONE_NEWNET, true
	case "ipc":
		return unix.CLONE_NEWIPC, true
	case "mnt":
		return unix.CLONE_NEWNS, true
	default:
		return 0, false
	}
}

func EnterNS(pid int, nsType string) int {
	nsFlag, ok := namespaceFlag(nsType)
	if !ok {
		return -1
	}

	path := fmt.Sprintf("/proc/%d/ns/%s", pid, nsType)
	selfPath := "/proc/self/ns/" + nsType

	oldnsStat, _ := os.Stat(selfPath)
	newnsStat, _ := os.Stat(path)
	if os.SameFile(oldnsStat, newnsStat) {
		return 0
	}

	newns, err := os.Open(path)
	if err != nil {
		return -1
	}
	defer newns.Close()

	// Joining a mount namespace via setns(CLONE_NEWNS) is rejected by the
	// kernel with EINVAL whenever the calling thread shares its filesystem
	// attributes (CLONE_FS: root dir, cwd, umask) with another thread. That is
	// always true on the Go runtime's thread pool, so give this thread a
	// private copy of those attributes first. The caller MUST have pinned the
	// goroutine to a dedicated, never-unlocked OS thread (see jvm.Attach):
	// once unshared and moved into a foreign namespace, the thread cannot be
	// safely recycled.
	if nsFlag == unix.CLONE_NEWNS {
		if err := unix.Unshare(unix.CLONE_FS); err != nil {
			return -1
		}
	}

	// Some ancient Linux distributions do not have setns() function
	if err := unix.Setns(int(newns.Fd()), nsFlag); err != nil {
		return -1
	}

	return 1
}

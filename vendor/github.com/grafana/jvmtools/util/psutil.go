package util

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	syscall "golang.org/x/sys/unix"
)

// Constants
const MaxPath = 4096

// Called just once to fill in tmpPath buffer
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
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line[4:])
			if len(fields) > 1 {
				*uid = int(parseUint32(fields[1]))
			}
		} else if strings.HasPrefix(line, "Gid:") {
			fields := strings.Fields(line[4:])
			if len(fields) > 1 {
				*gid = int(parseUint32(fields[1]))
			}
		} else if strings.HasPrefix(line, "NStgid:") {
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

	entries, _ := dir.Readdirnames(0)
	for _, entry := range entries {
		if entry[0] >= '1' && entry[0] <= '9' {
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

func EnterNS(pid int, nsType string) int {
	path := fmt.Sprintf("/proc/%d/ns/%s", pid, nsType)
	selfPath := fmt.Sprintf("/proc/self/ns/%s", nsType)

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

	// Some ancient Linux distributions do not have setns() function
	if _, _, err := syscall.RawSyscall(syscall.SYS_SETNS, newns.Fd(), syscall.CLONE_NEWNET, 0); err != 0 {
		return -1
	}

	return 1
}

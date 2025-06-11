package exec

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func FindNamespace(pid int32) (uint32, error) {
	pidPath := fmt.Sprintf("/proc/%d/ns/pid", pid)
	f, err := os.Open(pidPath)
	if err != nil {
		return 0, fmt.Errorf("failed to open(/proc/%d/ns/pid): %w", pid, err)
	}

	defer f.Close()

	// read the value of the symbolic link
	buf := make([]byte, syscall.PathMax)
	n, err := syscall.Readlink(pidPath, buf)
	if err != nil {
		return 0, fmt.Errorf("failed to read symlink(/proc/%d/ns/pid): %w", pid, err)
	}

	logger := slog.With("component", "pids.Tracer")

	nsPid := string(buf[:n])
	// extract u32 from the format pid:[nnnnn]
	start := strings.LastIndex(nsPid, "[")
	end := strings.LastIndex(nsPid, "]")

	logger.Debug("Found namespace", "nsPid", nsPid)

	if start >= 0 && end >= 0 && end > start {
		npid, err := strconv.ParseUint(string(buf[start+1:end]), 10, 32)
		if err != nil {
			return 0, fmt.Errorf("failed to parse ns pid %w", err)
		}

		return uint32(npid), nil
	}

	return 0, fmt.Errorf("couldn't find ns pid in the symlink [%s]", nsPid)
}

func FindNamespacedPids(pid int32) ([]uint32, error) {
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	f, err := os.Open(statusPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open(/proc/%d/status): %w", pid, err)
	}

	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "NSpid:") {
			l := line[6:]
			parts := strings.Split(l, "\t")
			result := make([]uint32, 0)
			for _, p := range parts {
				if len(p) == 0 {
					continue
				}
				id, err := strconv.ParseUint(p, 10, 32)

				if err == nil {
					result = append(result, uint32(id))
				} else {
					return nil, err
				}
			}
			return result, nil
		}
	}
	return nil, nil
}

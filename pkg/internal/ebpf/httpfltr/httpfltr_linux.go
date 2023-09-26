package httpfltr

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func findNamespace(pid int32) (uint32, error) {
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

	logger := slog.With("component", "httpfltr.Tracer")

	nsPid := string(buf[:n])
	// extract u32 from the format pid:[nnnnn]
	start := strings.LastIndex(nsPid, "[")
	end := strings.LastIndex(nsPid, "]")

	logger.Info("Found namespace", "nsPid", nsPid)

	if start >= 0 && end >= 0 && end > start {
		npid, err := strconv.ParseUint(string(buf[start+1:end]), 10, 32)

		if err != nil {
			return 0, fmt.Errorf("failed to parse ns pid %w", err)
		}

		return uint32(npid), nil
	}

	return 0, fmt.Errorf("couldn't find ns pid in the symlink [%s]", nsPid)
}

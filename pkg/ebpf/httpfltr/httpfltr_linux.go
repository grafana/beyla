package httpfltr

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/exp/slog"
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

func findSharedLib(lib string) (string, error) {
	o, err := exec.Command("ldconfig", "-p").Output()

	if err != nil {
		return "", err
	}

	out := string(o)

	sslPos := strings.Index(out, lib+" ")
	if sslPos < 0 {
		return "", fmt.Errorf("can't find %s in the shared libraries", lib)
	}

	pToPos := strings.Index(out[sslPos+1:], "=> ")
	if pToPos < 0 {
		return "", fmt.Errorf("wrong output from ldconfig")
	}
	pToPos += sslPos + 4

	end := strings.Index(out[pToPos:], "\n")

	if end < 0 {
		return "", fmt.Errorf("wrong output from ldconfig, can't find newline")
	}

	return string(out[pToPos : pToPos+end]), err
}

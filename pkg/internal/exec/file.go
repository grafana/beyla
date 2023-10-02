// Package goexec provides the utilities to analyse the executable code
package exec

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/shirou/gopsutil/net"
	"github.com/shirou/gopsutil/process"
)

// TODO: user-configurable
const retryTicker = 3 * time.Second

type ProcessReader interface {
	io.ReaderAt
	io.Closer
}

type FileInfo struct {
	CmdExePath     string
	ProExeLinkPath string
	ELF            *elf.File
	Pid            int32
	Ppid           int32
}

func (fi *FileInfo) ExecutableName() string {
	parts := strings.Split(fi.CmdExePath, "/")
	return parts[len(parts)-1]
}

// ProcessFinder allows finding a process given multiple criteria
type ProcessFinder func() ([]*process.Process, bool)

func log() *slog.Logger {
	return slog.With("component", "exec")
}

// ProcessNamed allows finding a Process whose name path contains the passed string
// TODO: use regular expression
func ProcessNamed(pathSuffix string) ProcessFinder {
	return func() ([]*process.Process, bool) {
		log := log().With("pathSuffix", pathSuffix)
		log.Debug("searching executable by process name")
		processes, err := process.Processes()
		if err != nil {
			log.Warn("can't get system processes", "error", err)
			return nil, false
		}
		for _, p := range processes {
			exePath, err := p.Exe()
			if err != nil {
				// expected for some processes, but it could also be due to insufficient permissions.
				// we check for insufficient permissions, log a warning, and continue
				if err := tryAccessPid(p.Pid); err != nil {
					log.Warn("can't get process information, possibly because of insufficient permissions", "process", p.Pid, "error", err)
				}
				continue
			}

			if strings.HasSuffix(exePath, pathSuffix) {
				return []*process.Process{p}, true
			}
		}
		return nil, false
	}
}

// OwnedPort allows finding a Process that owns the passed port
func OwnedPort(port int) ProcessFinder {
	return func() ([]*process.Process, bool) {
		var found []*process.Process
		log := log().With("port", port)
		log.Debug("searching executable by port number")
		processes, err := process.Processes()
		if err != nil {
			log.Warn("can't get system processes", "error", err)
			return nil, false
		}
		for _, p := range processes {
			conns, err := net.ConnectionsPid("all", p.Pid)
			if err != nil {
				log.Warn("can't get process connections. Ignoring", "process", p.Pid, "error", err)
				continue
			}

			if len(conns) == 0 {
				// there will be processes with no open file descriptors, but unfortunately the library we use to
				// get the connections for a given 'pid' swallows any permission errors. We ensure we didn't fail to
				// find the open file descriptors because of access permissions. If we did, we log a warning to let
				// the user know they may have configuration issues.
				if err := tryAccessPid(p.Pid); err != nil {
					log.Warn("can't get process information, possibly because of insufficient permissions", "process", p.Pid, "error", err)
					continue
				}
			}

			for _, c := range conns {
				if c.Laddr.Port == uint32(port) {
					comm, _ := p.Cmdline()
					log.Info("found process", "pid", p.Pid, "comm", comm)
					found = append(found, p)
				}
			}
		}

		return found, len(found) != 0
	}
}

func tryAccessPid(pid int32) error {
	dir := fmt.Sprintf("/proc/%d/fd", pid)
	_, err := os.Open(dir)
	return err
}

// findExecELF operation blocks until the executable is available.
// TODO: check that all the existing instances of the excutable are instrumented, even when it is offloaded from memory
func FindExecELF(ctx context.Context, finder ProcessFinder) ([]FileInfo, error) {
	var fileInfos []FileInfo
	for {
		log().Debug("searching for process executable")
		processes, ok := finder()
		if !ok {
			select {
			case <-ctx.Done():
				log().Debug("context was cancelled before finding the process. Exiting")
				return []FileInfo{}, errors.New("process not found")
			default:
				log().Debug("no processes found. Will retry", "retryAfter", retryTicker.String())
				time.Sleep(retryTicker)
			}
			continue
		}
		for _, p := range processes {
			exePath, err := p.Exe()
			if err != nil {
				// this might happen if you query from the port a service that does not have executable path.
				// Since this value is just for attributing, we set a default placeholder
				exePath = "unknown"
			}

			ppid, _ := p.Ppid()

			// In container environments or K8s, we can't just open the executable exe path, because it might
			// be in the volume of another pod/container. We need to access it through the /proc/<pid>/exe symbolic link
			file := FileInfo{
				CmdExePath: exePath,
				// TODO: allow overriding /proc root folder
				ProExeLinkPath: fmt.Sprintf("/proc/%d/exe", p.Pid),
				Pid:            p.Pid,
				Ppid:           ppid,
			}
			file.ELF, err = elf.Open(file.ProExeLinkPath)
			if err != nil {
				return fileInfos, fmt.Errorf("can't open ELF executable file %q: %w", exePath, err)
			}
			fileInfos = append(fileInfos, file)
		}

		return fileInfos, nil
	}
	// TODO: return error after X attempts?
}

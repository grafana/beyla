// Package goexec provides the utilities to analyse the executable code
package exec

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/shirou/gopsutil/net"
	"golang.org/x/exp/slog"

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
}

// ProcessFinder allows finding a process given multiple criteria
type ProcessFinder func() (*process.Process, bool)

func log() *slog.Logger {
	return slog.With("component", "exec")
}

// ProcessNamed allows finding a Process whose name path contains the passed string
// TODO: use regular expression
func ProcessNamed(pathSuffix string) ProcessFinder {
	return func() (*process.Process, bool) {
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
				// expected for many processes, so we just ignore and keep going
				continue
			}

			if strings.HasSuffix(exePath, pathSuffix) {
				return p, true
			}
		}
		return nil, false
	}
}

// OwnedPort allows finding a Process that owns the passed port
func OwnedPort(port int, ignorePids map[int32]bool) ProcessFinder {
	return func() (*process.Process, bool) {
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
			if ignorePids[p.Pid] {
				comm, _ := p.Cmdline()
				log.Info("Ignoring invalid process", "process", p.Pid, "comm", comm)
				continue
			}
			for _, c := range conns {
				if c.Laddr.Port == uint32(port) {
					return p, true
				}
			}
		}
		return nil, false
	}
}

// findExecELF operation blocks until the executable is available.
// TODO: check that all the existing instances of the excutable are instrumented, even when it is offloaded from memory
func FindExecELF(ctx context.Context, finder ProcessFinder) (FileInfo, error) {
	for {
		log().Debug("searching for process executable")
		p, ok := finder()
		if !ok {
			select {
			case <-ctx.Done():
				log().Debug("context was cancelled before finding the process. Exiting")
				return FileInfo{}, errors.New("process not found")
			default:
				log().Debug("no processes found. Will retry", "retryAfter", retryTicker.String())
				time.Sleep(retryTicker)
			}
			continue
		}
		exePath, err := p.Exe()
		if err != nil {
			// this might happen if you query from the port a service that does not have executable path.
			// Since this value is just for attributing, we set a default placeholder
			exePath = "unknown"
		}
		// In container environments or K8s, we can't just open the executable exe path, because it might
		// be in the volume of another pod/container. We need to access it through the /proc/<pid>/exe symbolic link
		file := FileInfo{
			CmdExePath: exePath,
			// TODO: allow overriding /proc root folder
			ProExeLinkPath: fmt.Sprintf("/proc/%d/exe", p.Pid),
			Pid:            p.Pid,
		}
		file.ELF, err = elf.Open(file.ProExeLinkPath)
		if err != nil {
			return file, fmt.Errorf("can't open ELF executable file %q: %w", exePath, err)
		}
		return file, nil
	}
	// TODO: return error after X attempts?
}

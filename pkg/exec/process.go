// Package exec provides the utilities to analyse the executable code
package exec

import (
	"debug/elf"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/shirou/gopsutil/process"
	"golang.org/x/exp/slog"
)

var flog = slog.With("component", "exec.FindExecELF")

// TODO: user-configurable
const retryTicker = 3 * time.Second

type ProcessReader interface {
	io.ReaderAt
	io.Closer
}

type File struct {
	CmdExePath     string
	ProExeLinkPath string
	ELF            *elf.File
}

// FindExecELF finds the ELF info of the first executable whose name contains the given string.
// It returns a reader to the file of the process executable. The returned file
// must be closed after its usage.
// The operation blocks until the executable is available.
// TODO: use regular expression
// TODO: check that all the existing instances of the excutable are instrumented, even when it is offloaded from memory
func FindExecELF(pathContains string) (File, error) {
	log := flog.With("pathContains", pathContains)
	for {
		log.Debug("searching for process executable")
		processes, err := process.Processes()
		if err != nil {
			return File{}, fmt.Errorf("getting system processes: %w", err)
		}
		for _, p := range processes {
			exePath, err := p.Exe()
			if err != nil {
				slog.Debug("couldn't get executable name for process. Ignoring",
					"pid", p.Pid, "error", err.Error())
				continue
			}
			if strings.Contains(exePath, pathContains) {
				// In container environments or K8s, we can't just open the executable exe path, because it might
				// be in the volume of another pod/container. We need to access it through the /proc/<pid>/exe symbolic link
				file := File{
					CmdExePath: exePath,
					// TODO: allow overriding /proc root folder
					ProExeLinkPath: fmt.Sprintf("/proc/%d/exe", p.Pid),
				}
				file.ELF, err = elf.Open(file.ProExeLinkPath)
				if err != nil {
					return file, fmt.Errorf("can't open ELF executable file %q: %w", exePath, err)
				}
				return file, nil
			}
		}
		log.Warn("no processes found. Will retry", "retryAfter", retryTicker.String())
		time.Sleep(retryTicker)
		// TODO: return error after X attempts?
	}
}

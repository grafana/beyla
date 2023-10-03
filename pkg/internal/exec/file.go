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

	"github.com/grafana/beyla/pkg/internal/ebpf/services"
	"github.com/grafana/beyla/pkg/internal/svc"
)

// TODO: user-configurable
const retryTicker = 3 * time.Second

type ProcessReader interface {
	io.ReaderAt
	io.Closer
}

type FileInfo struct {
	Service svc.ID

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

func log() *slog.Logger {
	return slog.With("component", "exec")
}

// ProcessMatch matches a found process with the first selection criteria it fulfilled.
type ProcessMatch struct {
	Criteria *services.Attributes
	Process  *process.Process
}

func findProcesses(criteria services.DefinitionCriteria) ([]ProcessMatch, error) {
	log := log().With("matcher", "FindProcesses")
	log.Debug("finding all the executables matching the defined criteria")
	processes, err := process.Processes()
	if err != nil {
		return nil, fmt.Errorf("can't get system processes: %w", err)
	}
	var matches []ProcessMatch
	for _, p := range processes {
		for i := range criteria {
			if matchProcess(log, p, &criteria[i]) {
				comm, _ := p.Cmdline()
				log.Info("found process", "pid", p.Pid, "comm", comm)
				matches = append(matches, ProcessMatch{Criteria: &criteria[i], Process: p})
				break
			}
		}
	}
	return matches, nil
}

func matchProcess(log *slog.Logger, p *process.Process, a *services.Attributes) bool {
	if !a.Path.IsSet() && a.OpenPorts.Len() == 0 {
		return false
	}
	if a.Path.IsSet() && !matchByExecutable(log, p, a) {
		return false
	}
	if a.OpenPorts.Len() > 0 {
		return matchByPort(log, p, a)
	}
	return true
}

func matchByPort(log *slog.Logger, p *process.Process, a *services.Attributes) bool {
	conns, err := net.ConnectionsPid("all", p.Pid)
	if err != nil {
		log.Warn("can't get process connections. Ignoring", "process", p.Pid, "error", err)
		return false
	}
	if len(conns) == 0 {
		// there will be processes with no open file descriptors, but unfortunately the library we use to
		// get the connections for a given 'pid' swallows any permission errors. We ensure we didn't fail to
		// find the open file descriptors because of access permissions. If we did, we log a warning to let
		// the user know they may have configuration issues.
		if err := tryAccessPid(p.Pid); err != nil {
			log.Warn("can't get process information, possibly because of insufficient permissions", "process", p.Pid, "error", err)
			return false
		}
	}
	for _, c := range conns {
		if a.OpenPorts.Matches(int(c.Laddr.Port)) {
			return true
		}
	}
	return false
}

func matchByExecutable(log *slog.Logger, p *process.Process, a *services.Attributes) bool {
	exePath, err := p.Exe()
	if err != nil {
		// expected for some processes, but it could also be due to insufficient permissions.
		// we check for insufficient permissions, log a warning, and continue
		if err := tryAccessPid(p.Pid); err != nil {
			log.Warn("can't get process information, possibly because of insufficient permissions", "process", p.Pid, "error", err)
		}
		return false
	}
	if !a.Path.MatchString(exePath) {
		return false
	}
	return true
}

func tryAccessPid(pid int32) error {
	dir := fmt.Sprintf("/proc/%d/fd", pid)
	_, err := os.Open(dir)
	return err
}

// findExecELF operation blocks until the executable is available.
// TODO: check that all the existing instances of the excutable are instrumented, even when it is offloaded from memory
func FindExecELFs(ctx context.Context, criteria services.DefinitionCriteria) ([]FileInfo, error) {
	var fileInfos []FileInfo
	log := log()
	for {
		log.Debug("searching for process executables")
		processMatches, err := findProcesses(criteria)
		if len(processMatches) == 0 || err != nil {
			select {
			case <-ctx.Done():
				log.Debug("context was cancelled before finding the process. Exiting")
				return []FileInfo{}, errors.New("process not found")
			default:
				log.Debug("no processes found. Will retry", "retryAfter", retryTicker.String())
				time.Sleep(retryTicker)
			}
			continue
		}
		for _, m := range processMatches {
			p := m.Process
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
				Service: svc.ID{
					Name:      m.Criteria.Name,
					Namespace: m.Criteria.Namespace,
				},
				CmdExePath: exePath,
				// TODO: allow overriding /proc root folder
				ProExeLinkPath: fmt.Sprintf("/proc/%d/exe", p.Pid),
				Pid:            p.Pid,
				Ppid:           ppid,
			}
			file.ELF, err = elf.Open(file.ProExeLinkPath)
			if err != nil {
				log.Warn("can't open ELF executable file. Ignoring process", "path", exePath, "error", err)
				continue
			}
			fileInfos = append(fileInfos, file)
		}

		return fileInfos, nil
	}
	// TODO: return error after X attempts?
}

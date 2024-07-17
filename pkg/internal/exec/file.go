// Package goexec provides the utilities to analyse the executable code
package exec

import (
	"debug/elf"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/grafana/beyla/pkg/internal/svc"
	"github.com/grafana/beyla/pkg/services"
)

type FileInfo struct {
	Service svc.ID

	CmdExePath     string
	ProExeLinkPath string
	ELF            *elf.File
	Pid            int32
	Ppid           int32
	Ino            uint64
	Ns             uint32
}

func (fi *FileInfo) ExecutableName() string {
	parts := strings.Split(fi.CmdExePath, "/")
	return parts[len(parts)-1]
}

func FindExecELF(p *services.ProcessInfo, svcID *svc.ID) (*FileInfo, error) {
	// In container environments or K8s, we can't just open the executable exe path, because it might
	// be in the volume of another pod/container. We need to access it through the /proc/<pid>/exe symbolic link
	ns, err := FindNamespace(p.Pid)
	if err != nil {
		return nil, fmt.Errorf("can't find namespace for PID=%d: %w", p.Pid, err)
	}
	file := FileInfo{
		Service:    *svcID,
		CmdExePath: p.ExePath,
		// TODO: allow overriding /proc root folder
		ProExeLinkPath: fmt.Sprintf("/proc/%d/exe", p.Pid),
		Pid:            p.Pid,
		Ppid:           p.PPid,
		Ns:             ns,
	}
	if file.ELF, err = elf.Open(file.ProExeLinkPath); err != nil {
		return nil, fmt.Errorf("can't open ELF file in %s: %w", file.ProExeLinkPath, err)
	}

	info, err := os.Stat(file.ProExeLinkPath)
	if err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil, fmt.Errorf("couldn't cast stat into syscall.Stat_t for %s", file.ProExeLinkPath)
		}
		file.Ino = stat.Ino
	} else {
		return nil, err
	}
	return &file, nil
}

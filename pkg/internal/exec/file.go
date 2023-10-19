// Package goexec provides the utilities to analyse the executable code
package exec

import (
	"debug/elf"
	"fmt"
	"strings"

	"github.com/grafana/beyla/pkg/internal/discover/services"
	"github.com/grafana/beyla/pkg/internal/svc"
)

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

func FindExecELF(p *services.ProcessInfo, svcID svc.ID) (*FileInfo, error) {
	// In container environments or K8s, we can't just open the executable exe path, because it might
	// be in the volume of another pod/container. We need to access it through the /proc/<pid>/exe symbolic link
	file := FileInfo{
		Service:    svcID,
		CmdExePath: p.ExePath,
		// TODO: allow overriding /proc root folder
		ProExeLinkPath: fmt.Sprintf("/proc/%d/exe", p.Pid),
		Pid:            p.Pid,
		Ppid:           p.PPid,
	}
	var err error
	if file.ELF, err = elf.Open(file.ProExeLinkPath); err != nil {
		return nil, fmt.Errorf("can't open ELF file in %s: %w", file.ProExeLinkPath, err)
	}
	return &file, nil
}

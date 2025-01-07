package exec

import (
	"path/filepath"
	"strings"

	"github.com/prometheus/procfs"
)

func FindLibMaps(pid int32) ([]*procfs.ProcMap, error) {
	proc, err := procfs.NewProc(int(pid))

	if err != nil {
		return nil, err
	}

	return proc.ProcMaps()
}

func LibPath(name string, maps []*procfs.ProcMap) *procfs.ProcMap {
	for _, m := range maps {
		if strings.Contains(m.Pathname, string(filepath.Separator)+name) {
			return m
		}
	}

	return nil
}

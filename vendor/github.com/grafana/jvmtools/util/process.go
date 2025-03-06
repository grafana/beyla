package util

import (
	"debug/elf"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/prometheus/procfs"
)

type FileInfo struct {
	FsInfo       fs.FileInfo
	Path         string
	Pid          int
	StartAddress uintptr
	EndAddress   uintptr
}

func FindLibMaps(pid int) ([]*procfs.ProcMap, error) {
	proc, err := procfs.NewProc(int(pid))

	if err != nil {
		return nil, err
	}

	return proc.ProcMaps()
}

func LibPath(name string, maps []*procfs.ProcMap) *procfs.ProcMap {
	for _, m := range maps {
		if strings.Contains(m.Pathname, name) {
			return m
		}
	}

	return nil
}

func FindLibJVM(pid int) (*FileInfo, error) {
	maps, err := FindLibMaps(pid)
	if err != nil {
		return nil, err
	}

	libMap := LibPath("libjvm.so", maps)

	if libMap == nil {
		return nil, fmt.Errorf("can't find libjvm.so in process %d maps", pid)
	}

	libPath := fmt.Sprintf("/proc/%d/map_files/%x-%x", pid, libMap.StartAddr, libMap.EndAddr)

	info, err := os.Stat(libPath)

	if err != nil {
		return nil, err
	}

	result := FileInfo{
		FsInfo:       info,
		Path:         libPath,
		Pid:          pid,
		StartAddress: libMap.StartAddr,
		EndAddress:   libMap.EndAddr,
	}

	return &result, nil
}

func GetELF(file *FileInfo) (*elf.File, error) {
	elfF, err := elf.Open(file.Path)
	if err != nil {
		return nil, fmt.Errorf("can't open ELF file in %s: %w", file.Path, err)
	}

	return elfF, nil
}

func LookupSymbols(file *FileInfo, elfF *elf.File, symbols map[string]struct{}) (map[string]uintptr, error) {
	syms, err := elfF.Symbols()

	if err != nil {
		return nil, err
	}

	result := map[string]uintptr{}

	for _, s := range syms {
		_, ok := symbols[s.Name]

		if !ok {
			continue
		}

		result[s.Name] = uintptr(s.Value) + file.StartAddress
	}

	return result, nil
}

package exec

import (
	"debug/elf"
)

func FindProcLanguage(pid int32, elfF *elf.File) string {
	return ""
}

func FindExeSymbols(f *elf.File) (map[string]Sym, error) {
	return nil
}

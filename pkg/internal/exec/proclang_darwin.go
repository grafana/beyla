package exec

import (
	"debug/elf"

	"github.com/grafana/beyla/pkg/internal/svc"
)

func FindProcLanguage(pid int32, elfF *elf.File) svc.InstrumentableType {
	return ""
}

func FindExeSymbols(f *elf.File) (map[string]Sym, error) {
	return nil
}

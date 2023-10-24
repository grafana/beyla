package exec

import (
	"debug/elf"

	"github.com/grafana/beyla/pkg/internal/svc"
)

func FindProcLanguage(_ int32, _ *elf.File) svc.InstrumentableType {
	return svc.InstrumentableGeneric
}

func FindExeSymbols(_ *elf.File) (map[string]Sym, error) {
	return nil, nil
}

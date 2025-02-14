package exec

import (
	"debug/elf"

	"github.com/grafana/beyla/v2/pkg/internal/svc"
)

func FindProcLanguage(_ int32, _ *elf.File, _ string) svc.InstrumentableType {
	return svc.InstrumentableGeneric
}

func FindExeSymbols(_ *elf.File, _ []string) (map[string]Sym, error) {
	return nil, nil
}

package exec

import (
	"fmt"
	"os"

	"github.com/grafana/beyla/v2/pkg/internal/fastelf"
	"github.com/grafana/beyla/v2/pkg/internal/svc"
)

func FindProcLanguage(pid int32) svc.InstrumentableType {
	maps, err := FindLibMaps(pid)

	if err != nil {
		return svc.InstrumentableGeneric
	}

	for _, m := range maps {
		t := instrumentableFromModuleMap(m.Pathname)
		if t != svc.InstrumentableGeneric {
			return t
		}
	}

	filePath, err := resolveProcBinary(pid)

	if err != nil {
		return svc.InstrumentableGeneric
	}

	t := findLanguageFromElf(filePath)

	if t != svc.InstrumentableGeneric {
		return t
	}

	t = instrumentableFromPath(filePath)
	if t != svc.InstrumentableGeneric {
		return t
	}

	bytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return svc.InstrumentableGeneric
	}
	return instrumentableFromEnviron(string(bytes))
}

func resolveProcBinary(pid int32) (string, error) {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)

	realPath, err := os.Readlink(exePath)

	if err != nil {
		return "", fmt.Errorf("failed to read process binary: %w", err)
	}

	return fmt.Sprintf("/proc/%d/root%s", pid, realPath), nil
}

func findLanguageFromElf(filePath string) svc.InstrumentableType {
	ctx, err := fastelf.NewElfContextFromFile(filePath)

	if err != nil {
		return svc.InstrumentableGeneric
	}

	defer ctx.Close()

	if ctx.HasSection(".gopclntab") {
		return svc.InstrumentableGolang
	}

	return matchExeSymbols(ctx)
}

func matchExeSymbols(ctx *fastelf.ElfContext) svc.InstrumentableType {
	for _, sec := range ctx.Sections {
		if sec.Type != SHT_SYMTAB && sec.Type != SHT_DYNSYM {
			continue
		}

		//FIXME bound checks
		strtab := ctx.Sections[sec.Link]
		strs := ctx.Data[strtab.Offset:]

		symCount := int(sec.Size / sec.Entsize)

		for i := 0; i < symCount; i++ {
			sym := ReadStruct[Elf64_Sym](ctx.Data, int(sec.Offset)+i*int(sec.Entsize))

			if sym == nil || SymType(sym.Info) != STT_FUNC || sym.Size == 0 || sym.Value == 0 {
				continue
			}

			name := GetCStringUnsafe(strs, sym.Name)

			t := instrumentableFromSymbolName(name)

			if t != svc.InstrumentableGeneric {
				return t
			}
		}
	}

	return svc.InstrumentableGeneric
}

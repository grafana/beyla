package exec

import (
	"fmt"
	"os"
	"time"

	"github.com/grafana/beyla/v2/pkg/internal/svc"
)

func FindProcLanguage(pid int32, elfF *os.File, path string) svc.InstrumentableType {
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

	if elfF == nil {
		pidPath := fmt.Sprintf("/proc/%d/exe", pid)
		elfF, err = os.Open(pidPath)

		if err != nil || elfF == nil {
			return svc.InstrumentableGeneric
		}
	}

	t := findLanguageFromElf(elfF)
	if t != svc.InstrumentableGeneric {
		return t
	}

	t = instrumentableFromPath(path)
	if t != svc.InstrumentableGeneric {
		return t
	}

	bytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return svc.InstrumentableGeneric
	}
	return instrumentableFromEnviron(string(bytes))
}

func findLanguageFromElf(elfF *os.File) svc.InstrumentableType {
	info, err := elfF.Stat()

	if err != nil {
		return svc.InstrumentableGeneric
	}

	ctx, err := NewElfContext(elfF, info.Size())

	if err != nil {
		return svc.InstrumentableGeneric
	}

	defer ctx.Close()

	if ctx.HasSection(".gopclntab") {
		return svc.InstrumentableGolang
	}

	return matchExeSymbols(ctx)
}

func contains(slice []string, value string) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}

	return false
}

func matchExeSymbols(ctx *ElfContext) svc.InstrumentableType {
	start := time.Now()

	defer func() {
		elapsed := time.Since(start)
		fmt.Printf("matchExeSymbols took %v us\n", elapsed.Microseconds())
	}()

	for _, sec := range ctx.Sections {
		if sec.Type != SYMTAB && sec.Type != DYNSYM {
			continue
		}

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

package exec

import "debug/elf"

type Sym struct {
	Off  uint64
	Len  uint64
	Prog *elf.Prog
}

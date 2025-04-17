package exec

import (
	"fmt"
	"math"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const SYMTAB = 2
const STRTAB = 3
const DYNSYM = 11
const STT_FUNC = 2

type Elf64_Ehdr struct {
	Ident     [16]byte
	Type      uint16
	Machine   uint16
	Version   uint32
	Entry     uint64
	Phoff     uint64
	Shoff     uint64
	Flags     uint32
	Ehsize    uint16
	Phentsize uint16
	Phnum     uint16
	Shentsize uint16
	Shnum     uint16
	Shstrndx  uint16
}

type Elf64_Phdr struct {
	Type   uint32
	Flags  uint32
	Offset uint64
	Vaddr  uint64
	Paddr  uint64
	Filesz uint64
	Memsz  uint64
	Align  uint64
}

type Elf64_Shdr struct {
	Name      uint32
	Type      uint32
	Flags     uint64
	Addr      uint64
	Offset    uint64
	Size      uint64
	Link      uint32
	Info      uint32
	Addralign uint64
	Entsize   uint64
}

type Elf64_Sym struct {
	Name  uint32
	Info  uint8
	Other uint8
	Shndx uint16
	Value uint64
	Size  uint64
}

func SymType(info uint8) uint8 {
	return info & 0xf
}

func GetCString(data []byte, offset uint32) string {
	end := offset
	for end < uint32(len(data)) && data[end] != 0 {
		end++
	}
	return string(data[offset:end])
}

func unsafeString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

func GetCStringUnsafe(strtab []byte, offset uint32) string {
	start := offset
	for offset < uint32(len(strtab)) && strtab[offset] != 0 {
		offset++
	}
	return unsafeString(strtab[start:offset])
}

func ReadStruct[T any](data []byte, offset int) *T {
	if len(data) < offset+int(unsafe.Sizeof(*new(T))) {
		return nil
	}
	return (*T)(unsafe.Pointer(&data[offset]))
}

type ElfContext struct {
	Hdr      *Elf64_Ehdr
	Segments []*Elf64_Phdr
	Sections []*Elf64_Shdr
	Data     []byte
}

func NewElfContext(file *os.File, fileSize int64) (*ElfContext, error) {
	if fileSize < math.MinInt || fileSize > math.MaxInt {
		return nil, fmt.Errorf("file size is too big")
	}

	data, err := unix.Mmap(int(file.Fd()), 0, int(fileSize), unix.PROT_READ, unix.MAP_PRIVATE)

	if err != nil {
		return nil, fmt.Errorf("failed to mmap file: %w", err)
	}

	//unix.Madvise(data, unix.MADV_RANDOM)
	//unix.Madvise(data, unix.MADV_WILLNEED)

	hdr := ReadStruct[Elf64_Ehdr](data, 0)

	if hdr == nil || string(hdr.Ident[:4]) != "\x7fELF" {
		return nil, fmt.Errorf("invalid ELF file")
	}

	ctx := ElfContext{Hdr: hdr, Data: data}

	ctx.Segments = make([]*Elf64_Phdr, hdr.Phnum)

	for i := 0; i < int(hdr.Phnum); i++ {
		off := int(hdr.Phoff) + i*int(hdr.Phentsize)
		ctx.Segments[i] = ReadStruct[Elf64_Phdr](data, off)
	}

	ctx.Sections = make([]*Elf64_Shdr, hdr.Shnum)

	for i := 0; i < int(hdr.Shnum); i++ {
		off := int(hdr.Shoff) + i*int(hdr.Shentsize)
		ctx.Sections[i] = ReadStruct[Elf64_Shdr](data, off)
	}

	return &ctx, nil
}

func (ctx *ElfContext) Close() {
	unix.Munmap(ctx.Data)
}

func (ctx *ElfContext) HasSymbol(symbol string) bool {
	start := time.Now()

	defer func() {
		elapsed := time.Since(start)
		fmt.Printf("HasSymbol took %v us\n", elapsed.Microseconds())
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

			if name == symbol {
				return true
			}
		}
	}

	return false
}

func (ctx *ElfContext) HasSection(section string) bool {
	start := time.Now()

	defer func() {
		elapsed := time.Since(start)
		fmt.Printf("HasSection took %v us\n", elapsed.Microseconds())
	}()

	shstrtab := ctx.Sections[ctx.Hdr.Shstrndx]
	shstrtabData := ctx.Data[shstrtab.Offset:]

	for _, sec := range ctx.Sections {
		if GetCStringUnsafe(shstrtabData, sec.Name) == section {
			return true
		}
	}

	return false
}

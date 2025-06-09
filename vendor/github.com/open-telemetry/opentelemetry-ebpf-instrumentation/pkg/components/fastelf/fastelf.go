package fastelf

import (
	"errors"
	"fmt"
	"math"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// revive and stylecheck linters complain about underscores and casing, but
// these are the caononical name for this constants, hence 'nolint'

const InvalidAddr = ^uint64(0)

//nolint:revive,stylecheck,staticcheck,ST1003
const (
	STT_NOTYPE  uint8 = 0  /* Unspecified type. */
	STT_OBJECT  uint8 = 1  /* Data object. */
	STT_FUNC    uint8 = 2  /* Function. */
	STT_SECTION uint8 = 3  /* Section. */
	STT_FILE    uint8 = 4  /* Source file. */
	STT_COMMON  uint8 = 5  /* Uninitialized common block. */
	STT_TLS     uint8 = 6  /* TLS object. */
	STT_LOOS    uint8 = 10 /* Reserved range for operating system */
	STT_HIOS    uint8 = 12 /*   specific semantics. */
	STT_LOPROC  uint8 = 13 /* reserved range for processor */
	STT_HIPROC  uint8 = 15 /*   specific semantics. */

	/* Non-standard symbol types. */
	STT_RELC      uint8 = 8  /* Complex relocation expression. */
	STT_SRELC     uint8 = 9  /* Signed complex relocation expression. */
	STT_GNU_IFUNC uint8 = 10 /* Indirect code object. */
)

//nolint:revive,stylecheck,staticcheck,ST1003
const (
	SHT_NULL           uint32 = 0          /* inactive */
	SHT_PROGBITS       uint32 = 1          /* program defined information */
	SHT_SYMTAB         uint32 = 2          /* symbol table section */
	SHT_STRTAB         uint32 = 3          /* string table section */
	SHT_RELA           uint32 = 4          /* relocation section with addends */ //nolint:misspell
	SHT_HASH           uint32 = 5          /* symbol hash table section */
	SHT_DYNAMIC        uint32 = 6          /* dynamic section */
	SHT_NOTE           uint32 = 7          /* note section */
	SHT_NOBITS         uint32 = 8          /* no space section */
	SHT_REL            uint32 = 9          /* relocation section - no addends */
	SHT_SHLIB          uint32 = 10         /* reserved - purpose unknown */
	SHT_DYNSYM         uint32 = 11         /* dynamic symbol table section */
	SHT_INIT_ARRAY     uint32 = 14         /* Initialization function pointers. */
	SHT_FINI_ARRAY     uint32 = 15         /* Termination function pointers. */
	SHT_PREINIT_ARRAY  uint32 = 16         /* Pre-initialization function ptrs. */
	SHT_GROUP          uint32 = 17         /* Section group. */
	SHT_SYMTAB_SHNDX   uint32 = 18         /* Section indexes (see SHN_XINDEX). */
	SHT_LOOS           uint32 = 0x60000000 /* First of OS specific semantics */
	SHT_GNU_ATTRIBUTES uint32 = 0x6ffffff5 /* GNU object attributes */
	SHT_GNU_HASH       uint32 = 0x6ffffff6 /* GNU hash table */
	SHT_GNU_LIBLIST    uint32 = 0x6ffffff7 /* GNU prelink library list */
	SHT_GNU_VERDEF     uint32 = 0x6ffffffd /* GNU version definition section */
	SHT_GNU_VERNEED    uint32 = 0x6ffffffe /* GNU version needs section */
	SHT_GNU_VERSYM     uint32 = 0x6fffffff /* GNU version symbol table */
	SHT_HIOS           uint32 = 0x6fffffff /* Last of OS specific semantics */
	SHT_LOPROC         uint32 = 0x70000000 /* reserved range for processor */
	SHT_MIPS_ABIFLAGS  uint32 = 0x7000002a /* .MIPS.abiflags */
	SHT_HIPROC         uint32 = 0x7fffffff /* specific section header types */
	SHT_LOUSER         uint32 = 0x80000000 /* reserved range for application */
	SHT_HIUSER         uint32 = 0xffffffff /* specific indexes */
)

//nolint:revive,stylecheck,staticcheck,ST1003
const (
	PT_NULL    uint32 = 0 /* Unused entry. */
	PT_LOAD    uint32 = 1 /* Loadable segment. */
	PT_DYNAMIC uint32 = 2 /* Dynamic linking information segment. */
	PT_INTERP  uint32 = 3 /* Pathname of interpreter. */
	PT_NOTE    uint32 = 4 /* Auxiliary information. */
	PT_SHLIB   uint32 = 5 /* Reserved (not used). */
	PT_PHDR    uint32 = 6 /* Location of program header itself. */
	PT_TLS     uint32 = 7 /* Thread local storage segment */

	PT_LOOS uint32 = 0x60000000 /* First OS-specific. */

	PT_GNU_EH_FRAME uint32 = 0x6474e550 /* Frame unwind information */
	PT_GNU_STACK    uint32 = 0x6474e551 /* Stack flags */
	PT_GNU_RELRO    uint32 = 0x6474e552 /* Read only after relocs */
	PT_GNU_PROPERTY uint32 = 0x6474e553 /* GNU property */
	PT_GNU_MBIND_LO uint32 = 0x6474e555 /* Mbind segments start */
	PT_GNU_MBIND_HI uint32 = 0x6474f554 /* Mbind segments finish */

	PT_PAX_FLAGS uint32 = 0x65041580 /* PAX flags */

	PT_OPENBSD_RANDOMIZE uint32 = 0x65a3dbe6 /* Random data */
	PT_OPENBSD_WXNEEDED  uint32 = 0x65a3dbe7 /* W^X violations */
	PT_OPENBSD_NOBTCFI   uint32 = 0x65a3dbe8 /* No branch target CFI */
	PT_OPENBSD_BOOTDATA  uint32 = 0x65a41be6 /* Boot arguments */

	PT_SUNW_EH_FRAME uint32 = 0x6474e550 /* Frame unwind information */
	PT_SUNWSTACK     uint32 = 0x6ffffffb /* Stack segment */

	PT_HIOS uint32 = 0x6fffffff /* Last OS-specific. */

	PT_LOPROC uint32 = 0x70000000 /* First processor-specific type. */

	PT_ARM_ARCHEXT uint32 = 0x70000000 /* Architecture compatibility */
	PT_ARM_EXIDX   uint32 = 0x70000001 /* Exception unwind tables */

	PT_AARCH64_ARCHEXT uint32 = 0x70000000 /* Architecture compatibility */
	PT_AARCH64_UNWIND  uint32 = 0x70000001 /* Exception unwind tables */

	PT_MIPS_REGINFO  uint32 = 0x70000000 /* Register usage */
	PT_MIPS_RTPROC   uint32 = 0x70000001 /* Runtime procedures */
	PT_MIPS_OPTIONS  uint32 = 0x70000002 /* Options */
	PT_MIPS_ABIFLAGS uint32 = 0x70000003 /* ABI flags */

	PT_S390_PGSTE uint32 = 0x70000000 /* 4k page table size */

	PT_HIPROC uint32 = 0x7fffffff /* Last processor-specific type. */
)

//nolint:revive,stylecheck,staticcheck,ST1003
const (
	PF_X        uint32 = 0x1        /* Executable. */
	PF_W        uint32 = 0x2        /* Writable. */
	PF_R        uint32 = 0x4        /* Readable. */
	PF_MASKOS   uint32 = 0x0ff00000 /* Operating system-specific. */
	PF_MASKPROC uint32 = 0xf0000000 /* Processor-specific. */
)

//nolint:revive,stylecheck,staticcheck,ST1003
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

//nolint:revive,stylecheck,staticcheck,ST1003
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

//nolint:revive,stylecheck,staticcheck,ST1003
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

//nolint:revive,stylecheck,staticcheck,ST1003
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

	file     *os.File
	ownsData bool
}

func NewElfContextFromFile(filePath string) (*ElfContext, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", filePath, err)
	}

	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to stat %s: %w", filePath, err)
	}

	ctx, err := NewElfContextFromFileHandle(file, info.Size())
	if err != nil {
		file.Close()
		return nil, err
	}

	ctx.file = file

	return ctx, nil
}

func NewElfContextFromFileHandle(file *os.File, fileSize int64) (*ElfContext, error) {
	if fileSize < math.MinInt || fileSize > math.MaxInt {
		return nil, errors.New("file size is too big")
	}

	data, err := unix.Mmap(int(file.Fd()), 0, int(fileSize), unix.PROT_READ, unix.MAP_PRIVATE)
	if err != nil {
		return nil, fmt.Errorf("failed to mmap file: %w", err)
	}

	ctx, err := NewElfContextFromData(data)
	if err != nil {
		_ = unix.Munmap(data)

		return nil, err
	}

	ctx.ownsData = true

	return ctx, nil
}

func NewElfContextFromData(data []byte) (*ElfContext, error) {
	hdr := ReadStruct[Elf64_Ehdr](data, 0)

	if hdr == nil {
		return nil, errors.New("invalid ELF file")
	}

	if unsafeString(hdr.Ident[:4]) != "\x7fELF" {
		return nil, errors.New("invalid ELF signature")
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

func (ctx *ElfContext) Close() error {
	if ctx.file != nil {
		defer ctx.file.Close()
	}

	if ctx.ownsData {
		if err := unix.Munmap(ctx.Data); err != nil {
			return fmt.Errorf("failed to unmap elf context: %w", err)
		}
	}

	return nil
}

func (ctx *ElfContext) HasSymbol(symbol string) bool {
	for _, sec := range ctx.Sections {
		if sec.Type != SHT_SYMTAB && sec.Type != SHT_DYNSYM {
			continue
		}

		if int(sec.Link) >= len(ctx.Sections) {
			continue
		}

		strtab := ctx.Sections[sec.Link]

		if int(strtab.Offset) >= len(ctx.Data) {
			continue
		}

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

func (ctx *ElfContext) HasSection(sectionName string) bool {
	return ctx.section(sectionName) != nil
}

func (ctx *ElfContext) SectionAddress(sectionName string) uint64 {
	s := ctx.section(sectionName)

	if s == nil {
		return InvalidAddr
	}

	return s.Addr
}

func (ctx *ElfContext) shstrtabData() []byte {
	if int(ctx.Hdr.Shstrndx) >= len(ctx.Sections) {
		return nil
	}

	shstrtab := ctx.Sections[ctx.Hdr.Shstrndx]

	if int(shstrtab.Offset) >= len(ctx.Data) {
		return nil
	}

	return ctx.Data[shstrtab.Offset:]
}

func (ctx *ElfContext) section(sectionName string) *Elf64_Shdr {
	shstrtabData := ctx.shstrtabData()

	if shstrtabData == nil {
		return nil
	}

	for _, sec := range ctx.Sections {
		if GetCStringUnsafe(shstrtabData, sec.Name) == sectionName {
			return sec
		}
	}

	return nil
}

// Package goexec provides the utilities to analyse the executable code
package goexec

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/shirou/gopsutil/net"

	"github.com/shirou/gopsutil/process"
)

// TODO: user-configurable
const retryTicker = 3 * time.Second

type ProcessReader interface {
	io.ReaderAt
	io.Closer
}

type FileInfo struct {
	CmdExePath     string
	ProExeLinkPath string
	ELF            *elf.File
}

// ProcessFinder allows finding a process given multiple criteria
type ProcessFinder func() (*process.Process, bool)

// ProcessNamed allows finding a Process whose name path contains the passed string
// TODO: use regular expression
func ProcessNamed(pathSuffix string) ProcessFinder {
	return func() (*process.Process, bool) {
		log := log().With("pathSuffix", pathSuffix)
		log.Debug("searching executable by process name")
		processes, err := process.Processes()
		if err != nil {
			log.Warn("can't get system processes", "error", err)
			return nil, false
		}
		for _, p := range processes {
			exePath, err := p.Exe()
			if err != nil {
				// expected for many processes, so we just ignore and keep going
				continue
			}

			if strings.HasSuffix(exePath, pathSuffix) {
				return p, true
			}
		}
		return nil, false
	}
}

// OwnedPort allows finding a Process that owns the passed port
func OwnedPort(port int) ProcessFinder {
	return func() (*process.Process, bool) {
		log := log().With("port", port)
		log.Debug("searching executable by port number")
		processes, err := process.Processes()
		if err != nil {
			log.Warn("can't get system processes", "error", err)
			return nil, false
		}
		for _, p := range processes {
			conns, err := net.ConnectionsPid("all", p.Pid)
			if err != nil {
				log.Warn("can't get process connections. Ignoring", "process", p.Pid, "error", err)
				continue
			}
			for _, c := range conns {
				if c.Laddr.Port == uint32(port) {
					return p, true
				}
			}
		}
		return nil, false
	}
}

// findExecELF operation blocks until the executable is available.
// TODO: check that all the existing instances of the excutable are instrumented, even when it is offloaded from memory
func findExecELF(finder ProcessFinder) (FileInfo, error) {
	for {
		log().Debug("searching for process executable")
		p, ok := finder()
		if !ok {
			log().Debug("no processes found. Will retry", "retryAfter", retryTicker.String())
			time.Sleep(retryTicker)
			continue
		}
		exePath, err := p.Exe()
		if err != nil {
			// this might happen if you query from the port a service that does not have executable path.
			// Since this value is just for attributing, we set a default placeholder
			exePath = "unknown"
		}
		// In container environments or K8s, we can't just open the executable exe path, because it might
		// be in the volume of another pod/container. We need to access it through the /proc/<pid>/exe symbolic link
		file := FileInfo{
			CmdExePath: exePath,
			// TODO: allow overriding /proc root folder
			ProExeLinkPath: fmt.Sprintf("/proc/%d/exe", p.Pid),
		}
		file.ELF, err = elf.Open(file.ProExeLinkPath)
		if err != nil {
			return file, fmt.Errorf("can't open ELF executable file %q: %w", exePath, err)
		}
		return file, nil
	}
	// TODO: return error after X attempts?
}

// findLibraryVersions looks for all the libraries and versions inside the elf file.
// It returns a map where the key is the library name and the value is the library version
func findLibraryVersions(elfFile *elf.File) (map[string]string, error) {
	goVersion, modules, err := getGoDetails(elfFile)
	if err != nil {
		return nil, fmt.Errorf("getting Go details: %w", err)
	}

	goVersion = strings.ReplaceAll(goVersion, "go", "")
	log().Debug("Go version detected", "version", goVersion)
	modsMap := parseModules(modules)
	modsMap["go"] = goVersion
	return modsMap, nil
}

// The build info blob left by the linker is identified by
// a 16-byte header, consisting of buildInfoMagic (14 bytes),
// the binary's pointer size (1 byte),
// and whether the binary is big endian (1 byte).
var buildInfoMagic = []byte("\xff Go buildinf:")

func getGoDetails(f *elf.File) (string, string, error) {
	data, err2 := getBuildInfoBlob(f)
	if err2 != nil {
		return "", "", err2
	}

	// Decode the blob.
	// The first 14 bytes are buildInfoMagic.
	// The next two bytes indicate pointer size in bytes (4 or 8) and endianness
	// (0 for little, 1 for big).
	// Two virtual addresses to Go strings follow that: runtime.buildVersion,
	// and runtime.modinfo.
	// On 32-bit platforms, the last 8 bytes are unused.
	// If the endianness has the 2 bit set, then the pointers are zero
	// and the 32-byte header is followed by varint-prefixed string data
	// for the two string values we care about.
	ptrSize := int(data[14])
	var vers, mod string
	if data[15]&2 != 0 {
		vers, data = decodeString(data[32:])
		mod, _ = decodeString(data)
	} else {
		bigEndian := data[15] != 0
		var bo binary.ByteOrder
		if bigEndian {
			bo = binary.BigEndian
		} else {
			bo = binary.LittleEndian
		}
		var readPtr func([]byte) uint64
		if ptrSize == 4 {
			readPtr = func(b []byte) uint64 { return uint64(bo.Uint32(b)) }
		} else {
			readPtr = bo.Uint64
		}
		vers = readString(f, ptrSize, readPtr, readPtr(data[16:]))
		mod = readString(f, ptrSize, readPtr, readPtr(data[16+ptrSize:]))
	}
	if vers == "" {
		return "", "", errors.New("not a Go executable")
	}
	if len(mod) >= 33 && mod[len(mod)-17] == '\n' {
		// Strip module framing: sentinel strings delimiting the module info.
		// These are cmd/go/internal/modload.infoStart and infoEnd.
		mod = mod[16 : len(mod)-16]
	} else {
		mod = ""
	}

	return vers, mod, nil
}

// getBuildInfoBlob reads the first 64kB of text to find the build info blob.
func getBuildInfoBlob(f *elf.File) ([]byte, error) {
	text := dataStart(f)
	data, err := readData(f, text, 64*1024)
	if err != nil {
		return nil, err
	}
	const (
		buildInfoAlign = 16
		buildInfoSize  = 32
	)
	for {
		i := bytes.Index(data, buildInfoMagic)
		if i < 0 || len(data)-i < buildInfoSize {
			return nil, errors.New("not a Go executable")
		}
		if i%buildInfoAlign == 0 && len(data)-i >= buildInfoSize {
			data = data[i:]
			break
		}
		data = data[(i+buildInfoAlign-1)&^buildInfoAlign:]
	}
	return data, nil
}

func dataStart(f *elf.File) uint64 {
	for _, s := range f.Sections {
		if s.Name == ".go.buildinfo" {
			return s.Addr
		}
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&(elf.PF_X|elf.PF_W) == elf.PF_W {
			return p.Vaddr
		}
	}
	return 0
}

func readData(f *elf.File, addr, size uint64) ([]byte, error) {
	for _, prog := range f.Progs {
		if prog.Vaddr <= addr && addr <= prog.Vaddr+prog.Filesz-1 {
			n := prog.Vaddr + prog.Filesz - addr
			if n > size {
				n = size
			}
			data := make([]byte, n)
			_, err := prog.ReadAt(data, int64(addr-prog.Vaddr))
			if err != nil {
				return nil, err
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("address not mapped")
}

// readString returns the string at address addr in the executable x.
func readString(f *elf.File, ptrSize int, readPtr func([]byte) uint64, addr uint64) string {
	hdr, err := readData(f, addr, uint64(2*ptrSize))
	if err != nil || len(hdr) < 2*ptrSize {
		return ""
	}
	dataAddr := readPtr(hdr)
	dataLen := readPtr(hdr[ptrSize:])
	data, err := readData(f, dataAddr, dataLen)
	if err != nil || uint64(len(data)) < dataLen {
		return ""
	}
	return string(data)
}

func parseModules(mod string) map[string]string {
	lines := strings.Split(mod, "\n")
	result := map[string]string{}
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) > 1 {
			modType := parts[0]
			modPackage := parts[1]
			if modType == "dep" {
				v := ""
				if len(parts) > 2 {
					v = parts[2]
				}
				log().Debug("library detected",
					"modType", modType,
					"modPackage", modPackage,
					"version", v)
				result[modPackage] = v
			}
		}
	}

	return result
}

func decodeString(data []byte) (s string, rest []byte) {
	u, n := binary.Uvarint(data)
	if n <= 0 || u >= uint64(len(data)-n) {
		return "", nil
	}
	return string(data[n : uint64(n)+u]), data[uint64(n)+u:]
}

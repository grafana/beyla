package ebpfcommon

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/grafana/beyla/pkg/internal/exec"
	"github.com/grafana/beyla/pkg/internal/request"
)

func ReadGPUKernelLaunchIntoSpan(record *ringbuf.Record, fileInfo *exec.FileInfo) (request.Span, bool, error) {
	var event GPUKernelLaunchInfo
	if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
		return request.Span{}, true, err
	}

	// Log the GPU Kernel Launch event
	slog.Debug("GPU Kernel Launch", "event", event)

	if fileInfo == nil || fileInfo.ELF == nil {
		return request.Span{}, true, errors.New("no ELF file information available")
	}

	symAddr, err := FindSymbolAddresses(fileInfo.ELF)
	if err != nil {
		return request.Span{}, true, fmt.Errorf("failed to find symbol addresses: %w", err)
	}

	// Find the symbol for the kernel launch
	symbol, ok := symAddr[event.KernFuncOff]
	if !ok {
		return request.Span{}, true, fmt.Errorf("failed to find symbol for kernel launch at address %d", event.KernFuncOff)
	}

	return request.Span{
		Type:   request.EventTypeGPUKernelLaunch,
		Method: symbol,
	}, false, nil
}

func collectSymbols(f *elf.File, syms []elf.Symbol, addressToName map[uint64]string) {
	for _, s := range syms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC {
			// Symbol not associated with a function or other executable code.
			continue
		}

		address := s.Value
		// Loop over ELF segments.
		for _, prog := range f.Progs {
			// Skip uninteresting segments.
			if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
				continue
			}

			if prog.Vaddr <= s.Value && s.Value < (prog.Vaddr+prog.Memsz) {
				address = s.Value - prog.Vaddr + prog.Off
				break
			}
		}
		addressToName[address] = s.Name
	}
}

// returns a map of symbol addresses to names
func FindSymbolAddresses(f *elf.File) (map[uint64]string, error) {
	addressToName := map[uint64]string{}
	syms, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}

	collectSymbols(f, syms, addressToName)

	dynsyms, err := f.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}

	collectSymbols(f, dynsyms, addressToName)

	return addressToName, nil
}

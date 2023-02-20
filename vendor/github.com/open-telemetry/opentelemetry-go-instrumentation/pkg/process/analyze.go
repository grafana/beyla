// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package process

import (
	"debug/elf"
	"debug/gosym"
	"errors"
	"fmt"
	"os"

	"github.com/prometheus/procfs"

	"github.com/hashicorp/go-version"
	"github.com/open-telemetry/opentelemetry-go-instrumentation/pkg/log"
	"golang.org/x/arch/x86/x86asm"
)

type TargetDetails struct {
	PID               int
	Functions         []*Func
	GoVersion         *version.Version
	Libraries         map[string]string
	AllocationDetails *AllocationDetails
}

type AllocationDetails struct {
	Addr    uint64
	EndAddr uint64
}

type Func struct {
	Name          string
	Offset        uint64
	ReturnOffsets []uint64
}

func (t *TargetDetails) IsRegistersABI() bool {
	regAbiMinVersion, _ := version.NewVersion("1.17")
	return t.GoVersion.GreaterThanOrEqual(regAbiMinVersion)
}

func (t *TargetDetails) GetFunctionOffset(name string) (uint64, error) {
	for _, f := range t.Functions {
		if f.Name == name {
			return f.Offset, nil
		}
	}

	return 0, fmt.Errorf("could not find offset for function %s", name)
}

func (t *TargetDetails) GetFunctionReturns(name string) ([]uint64, error) {
	for _, f := range t.Functions {
		if f.Name == name {
			return f.ReturnOffsets, nil
		}
	}

	return nil, fmt.Errorf("could not find returns for function %s", name)
}

func (a *processAnalyzer) findKeyvalMmap(pid int) (uintptr, uintptr) {
	fs, err := procfs.NewProc(pid)
	if err != nil {
		panic(err)
	}

	maps, err := fs.ProcMaps()
	if err != nil {
		panic(err)
	}

	for _, m := range maps {
		if m.Perms != nil && m.Perms.Read && m.Perms.Write && m.Perms.Execute {
			log.Logger.Info("found addr of keyval map", "addr", m.StartAddr)
			return m.StartAddr, m.EndAddr
		}
	}
	panic(errors.New("cant find keyval map"))
}

func (a *processAnalyzer) Analyze(pid int, relevantFuncs map[string]interface{}) (*TargetDetails, error) {
	result := &TargetDetails{
		PID: pid,
	}

	f, err := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return nil, err
	}

	defer f.Close()
	elfF, err := elf.NewFile(f)
	if err != nil {
		return nil, err
	}

	goVersion, modules, err := a.getModuleDetails(elfF)
	if err != nil {
		return nil, err
	}
	result.GoVersion = goVersion
	result.Libraries = modules

	start, end := a.findKeyvalMmap(pid)
	result.AllocationDetails = &AllocationDetails{
		Addr:    uint64(start),
		EndAddr: uint64(end),
	}

	var pclndat []byte
	if sec := elfF.Section(".gopclntab"); sec != nil {
		pclndat, err = sec.Data()
		if err != nil {
			return nil, err
		}
	}

	sec := elfF.Section(".gosymtab")
	if sec == nil {
		return nil, fmt.Errorf("%s section not found in target binary, make sure this is a Go application", ".gosymtab")
	}
	symTabRaw, err := sec.Data()
	pcln := gosym.NewLineTable(pclndat, elfF.Section(".text").Addr)
	symTab, err := gosym.NewTable(symTabRaw, pcln)
	if err != nil {
		return nil, err
	}

	for _, f := range symTab.Funcs {

		if _, exists := relevantFuncs[f.Name]; exists {
			start, returns, err := a.findFuncOffset(&f, elfF)
			if err != nil {
				return nil, err
			}

			log.Logger.V(0).Info("found relevant function for instrumentation", "function", f.Name, "returns", len(returns))
			function := &Func{
				Name:          f.Name,
				Offset:        start,
				ReturnOffsets: returns,
			}

			result.Functions = append(result.Functions, function)
		}
	}

	return result, nil
}

func (a *processAnalyzer) findFuncOffset(f *gosym.Func, elfF *elf.File) (uint64, []uint64, error) {
	off := f.Value
	for _, prog := range elfF.Progs {
		if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
			continue
		}

		// For more info on this calculation: stackoverflow.com/a/40249502
		if prog.Vaddr <= f.Value && f.Value < (prog.Vaddr+prog.Memsz) {
			off = f.Value - prog.Vaddr + prog.Off

			funcLen := f.End - f.Entry
			data := make([]byte, funcLen)
			_, err := prog.ReadAt(data, int64(f.Value-prog.Vaddr))
			if err != nil {
				log.Logger.Error(err, "error while finding function return")
				return 0, nil, err
			}

			var returns []uint64
			for i := 0; i < int(funcLen); {
				inst, err := x86asm.Decode(data[i:], 64)
				if err != nil {
					log.Logger.Error(err, "error while finding function return")
					return 0, nil, err
				}

				if inst.Op == x86asm.RET {
					returns = append(returns, off+uint64(i))
				}

				i += inst.Len
			}

			return off, returns, nil
		}

	}

	return 0, nil, fmt.Errorf("prog not found")
}

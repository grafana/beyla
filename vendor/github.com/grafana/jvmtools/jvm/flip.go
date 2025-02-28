package jvm

import (
	"fmt"

	"github.com/grafana/jvmtools/util"
)

const maxMemoryRetries = 5

type LoadStatus int

const (
	Error LoadStatus = iota
	LoadingAlreadyOn
	FailedToFindField
	FlippedFlag
)

func EnableDynamicAgentLoading(pid int) (LoadStatus, error) {
	info, err := util.FindLibJVM(pid)

	if err != nil {
		return Error, fmt.Errorf("encountered an error inspecting the processes for libjvm.so, error %v", err)
	}

	elfF, err := util.GetELF(info)

	if err != nil {
		return Error, fmt.Errorf("encountered an error opening elf file for libjvm.so, error %v", err)
	}

	symAddrs, err := util.LookupSymbols(info, elfF, map[string]struct{}{
		"gHotSpotVMStructs":                    {},
		"gHotSpotVMStructEntryTypeNameOffset":  {},
		"gHotSpotVMStructEntryFieldNameOffset": {},
		"gHotSpotVMStructEntryArrayStride":     {},
		"gHotSpotVMStructEntryIsStaticOffset":  {},
		"gHotSpotVMStructEntryAddressOffset":   {},
		"gHotSpotVMStructEntryOffsetOffset":    {},
		"gHotSpotVMTypes":                      {},
		"gHotSpotVMTypeEntryTypeNameOffset":    {},
		"gHotSpotVMTypeEntrySizeOffset":        {},
		"gHotSpotVMTypeEntryArrayStride":       {},
	})

	if err != nil {
		return Error, fmt.Errorf("encountered an error looking up symbol gHotSpotVMStructs, error %v", err)
	}

	javaProg, err := util.AttachToJavaProgram(info)

	if err != nil {
		javaProg.DetachFromJavaProgram()
		return Error, fmt.Errorf("encountered an error attaching to the java process, error %v", err)
	}

	var v map[string]uint64

	for i := 0; i < maxMemoryRetries; i++ {
		v, err = javaProg.ReadSymbolValues(symAddrs)
		if err == nil {
			break
		}
	}

	if err != nil {
		javaProg.DetachFromJavaProgram()
		return Error, fmt.Errorf("can't read program memory %v", err)
	}

	t := util.MakeTraverser(
		javaProg,
		v["gHotSpotVMStructEntryTypeNameOffset"],
		v["gHotSpotVMStructEntryFieldNameOffset"],
		v["gHotSpotVMStructEntryIsStaticOffset"],
		v["gHotSpotVMStructEntryAddressOffset"],
		v["gHotSpotVMStructEntryOffsetOffset"],
	)

	var fields map[string]map[string]util.Field

	for i := 0; i < maxMemoryRetries; i++ {
		fields, err = t.ReadEntries(v["gHotSpotVMStructs"], v["gHotSpotVMStructEntryArrayStride"])
		if err == nil {
			break
		}
	}

	if err != nil {
		javaProg.DetachFromJavaProgram()
		return Error, fmt.Errorf("can't read fields %v", err)
	}

	flagName := "Flag"
	flagsByType, ok := fields[flagName]

	if !ok {
		flagName = "JVMFlag"
		flagsByType, ok = fields[flagName]

		if !ok {
			javaProg.DetachFromJavaProgram()
			fmt.Printf("flags %v", fields)
			return Error, fmt.Errorf("JVMFlag not found, aborting ...")
		}
	}

	t = util.MakeTraverser(
		javaProg,
		v["gHotSpotVMTypeEntryTypeNameOffset"],
		0,
		0,
		0,
		v["gHotSpotVMTypeEntrySizeOffset"],
	)

	var fieldAddr uintptr

	for i := 0; i < maxMemoryRetries; i++ {
		fieldAddr, err = t.FindDynamicAgentLoading(flagName, flagsByType, v["gHotSpotVMTypes"], v["gHotSpotVMTypeEntryArrayStride"])
		if err == nil {
			break
		}
	}

	if err != nil {
		javaProg.DetachFromJavaProgram()
		return Error, fmt.Errorf("can't read JVM flag %v", err)
	}

	status := FailedToFindField

	if fieldAddr != 0 {
		var bytes []byte
		for i := 0; i < maxMemoryRetries; i++ {
			bytes, err = javaProg.ReadMemory(fieldAddr, 1)
			if err == nil {
				break
			}
		}

		if err != nil {
			javaProg.DetachFromJavaProgram()
			return Error, fmt.Errorf("failed to read field addr, error %v", err)
		}

		if bytes[0] == byte(0) {
			set := []byte{1}
			for i := 0; i < maxMemoryRetries; i++ {
				err = javaProg.WriteBufInfoMemory(fieldAddr, set, 1)
				if err == nil {
					break
				}
			}
			if err != nil {
				javaProg.DetachFromJavaProgram()
				return Error, fmt.Errorf("encountered error writing memory %v", err)
			}
			status = FlippedFlag
		} else {
			status = LoadingAlreadyOn
		}
	}

	javaProg.DetachFromJavaProgram()
	return status, nil
}

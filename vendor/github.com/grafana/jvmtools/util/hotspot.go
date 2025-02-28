package util

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type HotSpotFieldTraverser struct {
	program         *JavaProgram
	typeNameOffset  uint64
	fieldNameOffset uint64
	isStaticOffset  uint64
	addressOffset   uint64
	offsetOffset    uint64
	buf             []byte
}

type Field struct {
	offset uint64
	static bool
}

func MakeTraverser(p *JavaProgram, typeNameOffset, fieldNameOffset, isStaticOffset, addressOffset, offsetOffset uint64) *HotSpotFieldTraverser {
	return &HotSpotFieldTraverser{
		program:         p,
		typeNameOffset:  typeNameOffset,
		fieldNameOffset: fieldNameOffset,
		isStaticOffset:  isStaticOffset,
		addressOffset:   addressOffset,
		offsetOffset:    offsetOffset,
		buf:             make([]byte, 1024),
	}
}

func (t *HotSpotFieldTraverser) bufToStringA() string {
	l := bytes.IndexByte(t.buf, 0)

	if l < 0 {
		l = len(t.buf)
	}

	return string(t.buf[:l])
}

func (t *HotSpotFieldTraverser) GetStringAt(entry, offset uint64) (string, error) {
	err := t.program.ReadMemoryIntoBuf(uintptr(entry+offset), t.buf, 8)
	if err != nil {
		return "", err
	}
	ptr := binary.LittleEndian.Uint64(t.buf)
	t.program.ReadMemoryIntoBuf(uintptr(ptr), t.buf, 1024)
	return t.bufToStringA(), nil
}

func (t *HotSpotFieldTraverser) GetTypeName(entry uint64) (string, error) {
	return t.GetStringAt(entry, t.typeNameOffset)
}

func (t *HotSpotFieldTraverser) GetFieldName(entry uint64) (string, error) {
	return t.GetStringAt(entry, t.fieldNameOffset)
}

func (t *HotSpotFieldTraverser) IsStatic(entry uint64) (bool, error) {
	err := t.program.ReadMemoryIntoBuf(uintptr(entry+t.isStaticOffset), t.buf, 4)

	if err != nil {
		return false, err
	}

	val := binary.LittleEndian.Uint32(t.buf)

	return val == 1, nil
}

func (t *HotSpotFieldTraverser) GetOffset(entry uint64) (uint64, error) {
	if err := t.program.ReadMemoryIntoBuf(uintptr(entry+t.offsetOffset), t.buf, 4); err != nil {
		return 0, err
	}

	return uint64(binary.LittleEndian.Uint32(t.buf)), nil
}

func (t *HotSpotFieldTraverser) GetAddress(entry uint64) (uint64, error) {
	if err := t.program.ReadMemoryIntoBuf(uintptr(entry+t.addressOffset), t.buf, 8); err != nil {
		return 0, err
	}

	return binary.LittleEndian.Uint64(t.buf), nil
}

func (t *HotSpotFieldTraverser) ReadEntries(entry, stride uint64) (map[string]map[string]Field, error) {
	fields := map[string]map[string]Field{}

	for {
		fieldName, err := t.GetFieldName(entry)
		if err != nil || fieldName == "" {
			break
		}

		typeName, err := t.GetTypeName(entry)
		if err != nil {
			return nil, fmt.Errorf("error getting typeName, error %v", err)
		}

		isStatic, err := t.IsStatic(entry)

		if err != nil {
			return nil, fmt.Errorf("error getting isStatic, error %v", err)
		}

		var off uint64
		if isStatic {
			off, err = t.GetAddress(entry)
		} else {
			off, err = t.GetOffset(entry)
		}

		if err != nil {
			return nil, fmt.Errorf("error getting getAddress/getOffset, error %v", err)
		}

		fieldsByType, ok := fields[typeName]
		if !ok {
			fieldsByType = map[string]Field{}
			fields[typeName] = fieldsByType
		}

		fieldsByType[fieldName] = Field{
			offset: off,
			static: isStatic,
		}

		entry += stride
	}

	return fields, nil
}

func (t *HotSpotFieldTraverser) FindDynamicAgentLoading(flagName string, flagsByType map[string]Field, entry, stride uint64) (uintptr, error) {
	res := uintptr(0)
	for {
		typeName, err := t.GetTypeName(entry)
		if err != nil || typeName == "" {
			break
		}

		if flagName == typeName {
			size, err := t.GetOffset(entry)

			if err != nil {
				return 0, err
			}

			numFlagsField, ok := flagsByType["numFlags"]
			if !ok {
				return 0, fmt.Errorf("numFlags not found in flagsByType")
			}

			err = t.program.ReadMemoryIntoBuf(uintptr(numFlagsField.offset), t.buf, 4)

			if err != nil {
				return 0, err
			}

			numFlags := binary.LittleEndian.Uint32(t.buf)

			flagsField, ok := flagsByType["flags"]
			if !ok {
				return 0, fmt.Errorf("flags not found in flagsByType")
			}

			err = t.program.ReadMemoryIntoBuf(uintptr(flagsField.offset), t.buf, 8)

			if err != nil {
				return 0, err
			}

			baseFlagAddress := binary.LittleEndian.Uint64(t.buf)

			nameField, ok := flagsByType["_name"]
			if !ok {
				return 0, fmt.Errorf("_name not found in flagsByType")
			}

			addrField, ok := flagsByType["_addr"]
			if !ok {
				return 0, fmt.Errorf("_addr not found in flagsByType")
			}

			for k := 0; k < int(numFlags)-1; k++ {
				flagAddress := baseFlagAddress + uint64(k)*size

				err := t.program.ReadMemoryIntoBuf(uintptr(flagAddress+nameField.offset), t.buf, 8)

				if err != nil {
					return 0, err
				}

				flagPtr := binary.LittleEndian.Uint64(t.buf)

				err = t.program.ReadMemoryIntoBuf(uintptr(flagPtr), t.buf, 1024)

				if err != nil {
					return 0, err
				}

				flagName := t.bufToStringA()

				if flagName == "EnableDynamicAgentLoading" {
					err := t.program.ReadMemoryIntoBuf(uintptr(flagAddress+addrField.offset), t.buf, 8)
					if err != nil {
						return 0, err
					}

					fieldValueAddr := binary.LittleEndian.Uint64(t.buf)
					res = uintptr(fieldValueAddr)
				}
			}
		}
		entry += stride
	}

	return res, nil
}

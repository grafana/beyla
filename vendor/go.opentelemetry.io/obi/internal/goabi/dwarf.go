// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goabi // import "go.opentelemetry.io/obi/internal/goabi"

import (
	"debug/dwarf"
	"errors"
	"fmt"
	"strings"

	"go.opentelemetry.io/obi/internal/goversion"
)

// RuntimeUnit is the DWARF compile unit to which the Go linker attaches every
// Go type.
const RuntimeUnit = "runtime"

type dwarfQuery interface {
	name() string
	// unit returns the name of the compile unit that defines name.
	unit() string
	extract(*dwarf.Data, *dwarf.Entry) (uint64, bool, error)
}

type fieldQuery struct {
	typeName  string
	fieldName string
}

type sizeQuery struct {
	typeName string
}

type constantQuery struct {
	constantName string
}

// Extract discovers and validates a complete ABI from DWARF.
func Extract(data *dwarf.Data, targetVersion goversion.Version) (ABI, error) {
	if data == nil {
		return ABI{}, errors.New("missing DWARF data")
	}
	requested, err := requiredDefinitions(targetVersion)
	if err != nil {
		return ABI{}, err
	}
	// Reading only the compile units that define the requested names avoids
	// decoding the whole DWARF.
	return extractFromUnitsOrAll(data, requested, definingUnits(requested))
}

// extractFromUnitsOrAll extracts the ABI from the compile units in units, and
// from every compile unit if they are not enough.
func extractFromUnitsOrAll(data *dwarf.Data, requested []definition, units map[string]bool) (ABI, error) {
	abi, err := extractFromUnits(data, requested, units)
	if err == nil {
		return abi, nil
	}
	return extractFromUnits(data, requested, nil)
}

// extractFromUnits is Extract limited to the compile units in units, or to
// every compile unit if units is nil.
func extractFromUnits(data *dwarf.Data, requested []definition, units map[string]bool) (ABI, error) {
	values, err := readDWARF(data, requested, units)
	if err != nil {
		return ABI{}, err
	}
	return loadAndValidate(requested, func(requirement Requirement) (uint64, error) {
		value, ok := values[requirement.Key()]
		if !ok {
			return 0, errors.New("not found")
		}
		return value, nil
	})
}

func definingUnits(requested []definition) map[string]bool {
	units := map[string]bool{}
	for _, definition := range requested {
		units[definition.query.unit()] = true
	}
	return units
}

func (q fieldQuery) name() string {
	return q.typeName
}

func (q fieldQuery) unit() string {
	return RuntimeUnit
}

func (q fieldQuery) extract(data *dwarf.Data, entry *dwarf.Entry) (uint64, bool, error) {
	typeInfo, err := data.Type(entry.Offset)
	if err != nil {
		return 0, false, nil
	}
	structInfo, ok := typeInfo.(*dwarf.StructType)
	if !ok {
		return 0, false, nil
	}
	for _, field := range structInfo.Field {
		if field.Name != q.fieldName {
			continue
		}
		if field.ByteOffset < 0 {
			return 0, false, fmt.Errorf("negative offset for %s.%s", q.typeName, q.fieldName)
		}
		return uint64(field.ByteOffset), true, nil
	}
	return 0, false, nil
}

func (q sizeQuery) name() string {
	return q.typeName
}

func (q sizeQuery) unit() string {
	return RuntimeUnit
}

func (q sizeQuery) extract(_ *dwarf.Data, entry *dwarf.Entry) (uint64, bool, error) {
	value, err := unsignedValue(entry.Val(dwarf.AttrByteSize))
	if err != nil {
		return 0, false, nil
	}
	return value, true, nil
}

func (q constantQuery) name() string {
	return q.constantName
}

// unit returns the package path of the constant: a constant is defined in the
// compile unit of its package.
func (q constantQuery) unit() string {
	dot := strings.LastIndexByte(q.constantName, '.')
	if dot < 0 {
		return ""
	}
	return q.constantName[:dot]
}

func (q constantQuery) extract(_ *dwarf.Data, entry *dwarf.Entry) (uint64, bool, error) {
	if entry.Tag != dwarf.TagConstant {
		return 0, false, nil
	}
	value, err := unsignedValue(entry.Val(dwarf.AttrConstValue))
	if err != nil {
		return 0, false, fmt.Errorf("reading constant %s: %w", q.constantName, err)
	}
	return value, true, nil
}

// readDWARF reads the requested definitions from the compile units in units,
// or from every compile unit if units is nil.
func readDWARF(data *dwarf.Data, requested []definition, units map[string]bool) (map[string]uint64, error) {
	queries := map[string][]definition{}
	for _, definition := range requested {
		name := definition.query.name()
		queries[name] = append(queries[name], definition)
	}

	values := map[string]uint64{}
	reader := data.Reader()
	for {
		entry, err := reader.Next()
		if err != nil {
			return nil, err
		}
		if entry == nil {
			break
		}
		name, _ := entry.Val(dwarf.AttrName).(string)
		if entry.Tag == dwarf.TagCompileUnit && units != nil && !units[name] {
			reader.SkipChildren()
			continue
		}
		for _, definition := range queries[name] {
			value, found, err := definition.query.extract(data, entry)
			if err != nil {
				return nil, err
			}
			if !found {
				continue
			}
			if err := storeValue(values, definition.Key(), value); err != nil {
				return nil, err
			}
		}
	}
	return values, nil
}

func unsignedValue(value any) (uint64, error) {
	switch value := value.(type) {
	case int64:
		if value < 0 {
			return 0, errors.New("negative value")
		}
		return uint64(value), nil
	case uint64:
		return value, nil
	default:
		return 0, fmt.Errorf("unexpected DWARF value type %T", value)
	}
}

func storeValue(values map[string]uint64, key string, value uint64) error {
	if previous, ok := values[key]; ok && previous != value {
		return fmt.Errorf("conflicting values for %s: %d and %d", key, previous, value)
	}
	values[key] = value
	return nil
}

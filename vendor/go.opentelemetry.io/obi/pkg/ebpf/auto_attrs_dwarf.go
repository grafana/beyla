// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/ebpf"

import (
	"debug/dwarf"
	"debug/elf"
	"errors"
	"fmt"
	"strings"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/internal/gometa"
)

// BuildFunctionDWARFSpec covers ordinary functions whose signatures are not retained in runtime metadata.
func BuildFunctionDWARFSpec(ef *elf.File, span *config.CustomSpanSpec, cookie uint64, arch string) (CompiledCustomSpanSpec, []AutoAttrSlot, error) {
	if strings.Contains(span.FunctionSymbol(), "[") {
		return CompiledCustomSpanSpec{}, nil, fmt.Errorf("%w: generic function ABI", ErrAutoAttrsUnsupported)
	}
	data, err := ef.DWARF()
	if err != nil {
		return CompiledCustomSpanSpec{}, nil, err
	}
	signature, err := dwarfFunctionSignature(data, span.FunctionSymbol())
	if err != nil {
		return CompiledCustomSpanSpec{}, nil, err
	}
	abi, err := archForGometa(arch)
	if err != nil {
		return CompiledCustomSpanSpec{}, nil, err
	}
	args, err := gometa.BuildArgRecipe(signature, false, abi)
	if err != nil {
		return CompiledCustomSpanSpec{}, nil, err
	}
	compiled, slots, err := compileRecipes(span, cookie, args)
	if err != nil {
		return compiled, slots, err
	}
	returns, err := gometa.BuildArgRecipe(&gometa.FuncType{In: signature.Out}, false, abi)
	if err == nil {
		for i := range returns {
			returns[i].Name = "return" + strings.TrimPrefix(returns[i].Name, "arg")
		}
		result, resultSlots, err := compileRecipes(span, cookie, returns)
		if err == nil {
			compiled.Spec.ReturnArgs = result.Spec.Args
			compiled.Spec.ReturnArgCount = result.Spec.ArgCount
			for i := range resultSlots {
				resultSlots[i].Return = true
			}
			slots = append(slots, resultSlots...)
		}
	}
	return compiled, slots, nil
}

func dwarfFunctionSignature(data *dwarf.Data, name string) (*gometa.FuncType, error) {
	reader := data.Reader()
	for {
		entry, err := reader.Next()
		if err != nil {
			return nil, err
		}
		if entry == nil {
			break
		}
		if entry.Tag != dwarf.TagSubprogram || entry.Val(dwarf.AttrName) != name || !entry.Children {
			continue
		}
		signature := &gometa.FuncType{}
		for {
			param, err := reader.Next()
			if err != nil {
				return nil, err
			}
			if param == nil || param.Tag == 0 {
				return signature, nil
			}
			if param.Tag == dwarf.TagFormalParameter {
				offset, ok := param.Val(dwarf.AttrType).(dwarf.Offset)
				if !ok {
					return nil, errors.New("parameter type missing")
				}
				typ, err := data.Type(offset)
				if err != nil {
					return nil, err
				}
				t := dwarfArgumentType(typ)
				if t == nil {
					return nil, fmt.Errorf("unsupported parameter type %s", typ)
				}
				if output, _ := param.Val(dwarf.AttrVarParam).(bool); output {
					signature.Out = append(signature.Out, t)
				} else {
					signature.In = append(signature.In, t)
				}
			}
			if param.Children {
				reader.SkipChildren()
			}
		}
	}
	return nil, fmt.Errorf("DWARF signature for %q not found", name)
}

func dwarfArgumentType(t dwarf.Type) *gometa.Type {
	if alias, ok := t.(*dwarf.TypedefType); ok {
		return dwarfArgumentType(alias.Type)
	}
	result := &gometa.Type{Size: uint64(t.Size())}
	switch t := t.(type) {
	case *dwarf.BoolType:
		result.Kind = gometa.Bool
	case *dwarf.IntType:
		result.Kind = gometa.Int64
	case *dwarf.UintType, *dwarf.CharType, *dwarf.UcharType:
		result.Kind = gometa.Uint64
	case *dwarf.FloatType:
		result.Kind = gometa.Float64
	case *dwarf.PtrType, *dwarf.FuncType:
		result.Kind = gometa.Map // One integer ABI slot; opaque values are not captured.
	case *dwarf.StructType:
		name := t.StructName
		switch {
		case name == "string":
			result.Kind = gometa.String
		case strings.HasPrefix(name, "[]"):
			result.Kind = gometa.Slice
		case strings.HasPrefix(name, "interface {") || (len(t.Field) == 2 && (t.Field[0].Name == "tab" || t.Field[0].Name == "_type") && t.Field[1].Name == "data"):
			result.Kind = gometa.Interface
		default:
			return nil
		}
	default:
		return nil
	}
	return result
}

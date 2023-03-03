package goexec

import (
	"debug/dwarf"
	"fmt"

	"golang.org/x/exp/slog"
)

var log = slog.With("component", "goexec.structMemberOffsetsFromDwarf")

// TODO: make overridable by user
var structMembers = map[string]map[string]string{
	"net/http.Request": {
		"URL":    "url_ptr_pos",
		"Method": "method_ptr_pos",
	},
	"net/url.URL": {
		"Path": "path_ptr_pos",
	},
	"net/http.response": {
		"status": "status_ptr_pos",
	},
}

// level-1 key = Struct type name
// level-2 key = name of the field
// level-2 value = C constant name to override (e.g. path_ptr_pos)
func structMemberOffsetsFromDwarf(data *dwarf.Data) (FieldOffsets, error) {
	expectedReturns := map[string]struct{}{}
	for _, fields := range structMembers {
		for _, ctName := range fields {
			expectedReturns[ctName] = struct{}{}
		}
	}
	checkAllFound := func() error {
		if len(expectedReturns) > 0 {
			return fmt.Errorf("not all the fields were found: %v", expectedReturns)
		}
		return nil
	}
	log.Debug("searching offests for field constants", "constants", expectedReturns)

	fieldOffsets := FieldOffsets{}
	reader := data.Reader()
	for {
		entry, err := reader.Next()
		if err != nil {
			return fieldOffsets, fmt.Errorf("can't read DWARF data: %w", err)
		}
		if entry == nil { // END of dwarf data
			return fieldOffsets, checkAllFound()
		}
		if entry.Tag != dwarf.TagStructType {
			continue
		}
		attrs := getAttrs(entry)
		typeName := attrs[dwarf.AttrName].(string)
		if fields, ok := structMembers[typeName]; !ok {
			reader.SkipChildren()
			continue
		} else {
			log.Debug("inspecting fields for struct type", "type", typeName)
			if err := readMembers(reader, fields, expectedReturns, fieldOffsets); err != nil {
				return nil, fmt.Errorf("reading type %q members: %w", typeName, err)
			}
		}
	}
}

func readMembers(
	reader *dwarf.Reader,
	fields map[string]string,
	expectedReturns map[string]struct{},
	offsets FieldOffsets,
) error {
	for {
		entry, err := reader.Next()
		if err != nil {
			return fmt.Errorf("can't read DWARF data: %w", err)
		}
		if entry == nil { // END of dwarf data
			return nil
		}
		// Nil tag: end of the members list
		if entry.Tag == 0 {
			return nil
		}
		attrs := getAttrs(entry)
		if constName, ok := fields[attrs[dwarf.AttrName].(string)]; ok {
			delete(expectedReturns, constName)
			value := attrs[dwarf.AttrDataMemberLoc]
			log.Debug("found struct member offset",
				"const", constName, "offset", attrs[dwarf.AttrDataMemberLoc])
			offsets[constName] = uint64(value.(int64))
		}
	}
}

func getAttrs(entry *dwarf.Entry) map[dwarf.Attr]any {
	attrs := map[dwarf.Attr]any{}
	for f := range entry.Field {
		attrs[entry.Field[f].Attr] = entry.Field[f].Val
	}
	return attrs
}

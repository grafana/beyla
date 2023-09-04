package goexec

import (
	"bytes"
	"debug/dwarf"
	"debug/elf"
	_ "embed"
	"fmt"
	"strings"

	"golang.org/x/exp/slog"

	"github.com/grafana/go-offsets-tracker/pkg/offsets"
)

func log() *slog.Logger {
	return slog.With("component", "goexec.structMemberOffsets")
}

//go:embed offsets.json
var prefetchedOffsets string

type structInfo struct {
	// lib is the name of the library where the struct is defined.
	// "go" for the standar library or e.g. "google.golang.org/grpc"
	lib string
	// fields of the struct as key, and the name of the constant defined in the eBPF code as value
	fields map[string]string
}

// level-1 key = Struct type name and its containing library
// level-2 key = name of the field
// level-3 value = C constant name to override (e.g. path_ptr_pos)
var structMembers = map[string]structInfo{
	"net/http.Request": {
		lib: "go",
		fields: map[string]string{
			"URL":           "url_ptr_pos",
			"Method":        "method_ptr_pos",
			"RemoteAddr":    "remoteaddr_ptr_pos",
			"Host":          "host_ptr_pos",
			"ContentLength": "content_length_ptr_pos",
			"Header":        "req_header_ptr_pos",
		},
	},
	"net/url.URL": {
		lib: "go",
		fields: map[string]string{
			"Path": "path_ptr_pos",
		},
	},
	"net/http.response": {
		lib: "go",
		fields: map[string]string{
			"status": "status_ptr_pos",
			"req":    "resp_req_pos",
		},
	},
	"net/http.Response": {
		lib: "go",
		fields: map[string]string{
			"StatusCode": "status_code_ptr_pos",
		},
	},
	"google.golang.org/grpc/internal/transport.Stream": {
		lib: "google.golang.org/grpc",
		fields: map[string]string{
			"st":     "grpc_stream_st_ptr_pos",
			"method": "grpc_stream_method_ptr_pos",
		},
	},
	"google.golang.org/grpc/internal/status.Status": {
		lib: "google.golang.org/grpc",
		fields: map[string]string{
			"s": "grpc_status_s_pos",
		},
	},
	"google.golang.org/genproto/googleapis/rpc/status.Status": {
		lib: "google.golang.org/genproto",
		fields: map[string]string{
			"Code": "grpc_status_code_ptr_pos",
		},
	},
	"google.golang.org/grpc/internal/transport.http2Server": {
		lib: "google.golang.org/grpc",
		fields: map[string]string{
			"remoteAddr": "grpc_st_remoteaddr_ptr_pos",
			"localAddr":  "grpc_st_localaddr_ptr_pos",
		},
	},
	"net.TCPAddr": {
		lib: "go",
		fields: map[string]string{
			"IP":   "tcp_addr_ip_ptr_pos",
			"Port": "tcp_addr_port_ptr_pos",
		},
	},
	"google.golang.org/grpc.ClientConn": {
		lib: "google.golang.org/grpc",
		fields: map[string]string{
			"target": "grpc_client_target_ptr_pos",
		},
	},
}

func structMemberOffsets(elfFile *elf.File) (FieldOffsets, error) {
	// first, try to read offsets from DWARF debug info
	var offs FieldOffsets
	var expected map[string]struct{}
	dwarfData, err := elfFile.DWARF()
	if err == nil {
		offs, expected = structMemberOffsetsFromDwarf(dwarfData)

		if len(expected) > 0 {
			log().Debug("Fields not found in the DWARF file", "fields", expected)
		} else {
			return offs, nil
		}
	} else {
		// initialize empty offsets
		offs = FieldOffsets{}
	}

	log().Debug("Can't read all offsets from DWARF info. Checking in prefetched database")

	// if it is not possible, query from prefetched offsets
	return structMemberPreFetchedOffsets(elfFile, offs)
}

func structMemberPreFetchedOffsets(elfFile *elf.File, fieldOffsets FieldOffsets) (FieldOffsets, error) {
	log := log().With("function", "structMemberPreFetchedOffsets")
	offs, err := offsets.Read(bytes.NewBufferString(prefetchedOffsets))
	if err != nil {
		return nil, fmt.Errorf("reading offsets file contents: %w", err)
	}
	libVersions, err := findLibraryVersions(elfFile)
	if err != nil {
		return nil, fmt.Errorf("searching for library versions: %w", err)
	}
	// after putting the offsets.json in a Go structure, we search all the
	// structMembers elements on it, to get the annotated offsets
	for strName, strInfo := range structMembers {
		version, ok := libVersions[strInfo.lib]
		if !ok {
			log.Debug("can't find version for library", "lib", strInfo.lib)
			continue
		}

		dash := strings.Index(version, "-")
		if dash > 0 {
			version = version[:dash]
		}

		for fieldName, constantName := range strInfo.fields {
			// look the version of the required field in the offsets.json memory copy
			offset, ok := offs.Find(strName, fieldName, version)
			if !ok {
				log.Debug("can't find offsets for field",
					"lib", strInfo.lib, "name", strName, "field", fieldName, "version", version)
				continue
			}
			fieldOffsets[constantName] = offset
		}
	}
	return fieldOffsets, nil
}

// structMemberOffsetsFromDwarf reads the executable dwarf information to get
// the offsets specified in the structMembers map
func structMemberOffsetsFromDwarf(data *dwarf.Data) (FieldOffsets, map[string]struct{}) {
	log := log().With("function", "structMemberOffsetsFromDwarf")
	expectedReturns := map[string]struct{}{}
	for _, str := range structMembers {
		for _, ctName := range str.fields {
			expectedReturns[ctName] = struct{}{}
		}
	}
	log.Debug("searching offests for field constants", "constants", expectedReturns)

	fieldOffsets := FieldOffsets{}
	reader := data.Reader()
	for {
		entry, err := reader.Next()
		if err != nil {
			log.Debug("error reading DRWARF info", "data", err)
			return fieldOffsets, expectedReturns
		}
		if entry == nil { // END of dwarf data
			return fieldOffsets, expectedReturns
		}
		if entry.Tag != dwarf.TagStructType {
			continue
		}
		attrs := getAttrs(entry)
		typeName := attrs[dwarf.AttrName].(string)
		if structMember, ok := structMembers[typeName]; !ok {
			reader.SkipChildren()
			continue
		} else { //nolint:revive
			log.Debug("inspecting fields for struct type", "type", typeName)
			if err := readMembers(reader, structMember.fields, expectedReturns, fieldOffsets); err != nil {
				log.Debug("error reading DRWARF info", "type", typeName, "members", err)
				return nil, expectedReturns
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
			log().Debug("found struct member offset",
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

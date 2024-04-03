package goexec

import (
	"bytes"
	"debug/dwarf"
	"debug/elf"
	_ "embed"
	"fmt"
	"log/slog"
	"strings"

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
			"ctx":    "grpc_stream_ctx_ptr_pos",
		},
	},
	"google.golang.org/grpc/internal/status.Status": {
		lib: "google.golang.org/grpc",
		fields: map[string]string{
			"s": "grpc_status_s_pos",
		},
	},
	"google.golang.org/grpc/peer.Peer": {
		lib: "google.golang.org/grpc",
		fields: map[string]string{
			"Addr":      "grpc_peer_addr_pos",
			"LocalAddr": "grpc_peer_localaddr_pos",
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
			"peer":       "grpc_st_peer_ptr_pos",
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
	"bufio.Writer": {
		lib: "go",
		fields: map[string]string{
			"buf": "io_writer_buf_ptr_pos",
			"n":   "io_writer_n_pos",
		},
	},
	"context.valueCtx": {
		lib: "go",
		fields: map[string]string{
			"val": "value_context_val_ptr_pos",
		},
	},
	"google.golang.org/grpc/internal/transport.http2Client": {
		lib: "google.golang.org/grpc",
		fields: map[string]string{
			"nextID": "http2_client_next_id_pos",
		},
	},
	"golang.org/x/net/http2.responseWriterState": {
		lib: "golang.org/x/net",
		fields: map[string]string{
			"req":    "rws_req_pos",
			"status": "rws_status_pos",
		},
	},
	"golang.org/x/net/http2.ClientConn": {
		lib: "golang.org/x/net",
		fields: map[string]string{
			"nextStreamID": "cc_next_stream_id_pos",
		},
	},
	"golang.org/x/net/http2.Framer": {
		lib: "golang.org/x/net",
		fields: map[string]string{
			"w": "framer_w_pos",
		},
	},
	"net/http.conn": {
		lib: "go",
		fields: map[string]string{
			"rwc": "c_rwc_pos",
		},
	},
	"net.TCPConn": {
		lib: "go",
		fields: map[string]string{
			"conn": "rwc_conn_pos",
		},
	},
	"net.conn": {
		lib: "go",
		fields: map[string]string{
			"fd": "conn_fd_pos",
		},
	},
	"net.netFD": {
		lib: "go",
		fields: map[string]string{
			"laddr": "fd_laddr_pos",
			"raddr": "fd_raddr_pos",
		},
	},
	"net/http.persistConn": {
		lib: "go",
		fields: map[string]string{
			"conn": "pc_conn_pos",
		},
	},
	"google.golang.org/grpc/internal/transport.bufWriter": {
		lib: "google.golang.org/grpc",
		fields: map[string]string{
			"buf":    "grpc_transport_buf_writer_buf_pos",
			"offset": "grpc_transport_buf_writer_offset_pos",
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
			log.Debug("can't find version for library. Assuming 0.0.0", "lib", strInfo.lib)
			// unversioned libraries are accounted as "0.0.0" in offsets.json file
			// https://github.com/grafana/go-offsets-tracker/blob/main/pkg/writer/writer.go#L108-L110
			version = "0.0.0"
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
			log.Debug("found offset", "constantName", constantName, "offset", offset)
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
		typeName, ok := attrs[dwarf.AttrName]
		if !ok {
			reader.SkipChildren()
			continue
		}
		structMember, ok := structMembers[typeName.(string)]
		if !ok {
			reader.SkipChildren()
			continue
		}
		log.Debug("inspecting fields for struct type", "type", typeName)
		if err := readMembers(reader, structMember.fields, expectedReturns, fieldOffsets); err != nil {
			log.Debug("error reading DWARF info", "type", typeName, "error", err)
			return nil, expectedReturns
		}
	}
}

type dwarfReader interface {
	Next() (*dwarf.Entry, error)
}

func readMembers(
	reader dwarfReader,
	fields map[string]string,
	expectedReturns map[string]struct{},
	offsets FieldOffsets,
) error {
	log := log()
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
			value := attrs[dwarf.AttrDataMemberLoc]
			if constLocation, ok := value.(int64); ok {
				delete(expectedReturns, constName)
				log.Debug("found struct member offset",
					"const", constName, "offset", attrs[dwarf.AttrDataMemberLoc])
				offsets[constName] = uint64(constLocation)
			} else {
				// Temporary workaround
				return fmt.Errorf("at the moment, Beyla only supports constant values for DW_AT_data_member_location;"+
					"got %s. Beyla will read the offsets from a pre-fetched database", attrs[dwarf.AttrDataMemberLoc])
			}
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

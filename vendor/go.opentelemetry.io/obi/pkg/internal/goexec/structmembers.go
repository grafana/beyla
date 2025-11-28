// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

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
	"github.com/hashicorp/go-version"
)

func log() *slog.Logger {
	return slog.With("component", "goexec.structMemberOffsets")
}

// this const table must match what's in go_offsets.h
type GoOffset uint32

var (
	grpcOneSixZero      = version.Must(version.NewVersion("1.60.0"))
	grpcOneSixNine      = version.Must(version.NewVersion("1.69.0"))
	mongoOneThirteenOne = version.Must(version.NewVersion("1.13.1"))
)

const (
	// go common
	ConnFdPos GoOffset = iota + 1 // start at 1, must match what's in go_offsets.h
	FdLaddrPos
	FdRaddrPos
	TCPAddrPortPtrPos
	TCPAddrIPPtrPos
	// http
	URLPtrPos
	PathPtrPos
	HostPtrPos
	SchemePtrPos
	MethodPtrPos
	StatusCodePtrPos
	ResponseLengthPtrPos
	ContentLengthPtrPos
	ReqHeaderPtrPos
	IoWriterBufPtrPos
	IoWriterNPos
	CcNextStreamIDPos
	CcNextStreamIDVendoredPos
	CcFramerPos
	CcFramerVendoredPos
	FramerWPos
	PcConnPos
	PcTLSPos
	NetConnPos
	CcTconnPos
	CcTconnVendoredPos
	ScConnPos
	CRwcPos
	CTlsPos
	// grpc
	GrpcStreamStPtrPos
	GrpcStreamMethodPtrPos
	GrpcStatusSPos
	GrpcStatusCodePtrPos
	MetaHeadersFrameFieldsPtrPos
	ValueContextValPtrPos
	GrpcStConnPos
	GrpcTConnPos
	GrpcTSchemePos
	GrpcTransportStreamIDPos
	GrpcTransportBufWriterBufPos
	GrpcTransportBufWriterOffsetPos
	GrpcTransportBufWriterConnPos
	// redis
	RedisConnBwPos
	// kafka go
	KafkaGoWriterTopicPos
	KafkaGoProtocolConnPos
	KafkaGoReaderTopicPos
	// kafka sarama
	SaramaBrokerCorrIDPos
	SaramaResponseCorrIDPos
	SaramaBrokerConnPos
	SaramaBufconnConnPos
	// grpc versioning
	GrpcOneSixZero
	GrpcOneSixNine
	// grpc 1.69
	GrpcServerStreamStream
	GrpcServerStreamStPtr
	GrpcClientStreamStream
	// go manual spans
	GoTracerDelegatePos
	GoTracerAttributeOptOffset
	GoErrorStringOffset
	// go jsonrpc
	GoJsonrpcRequestHeaderServiceMethodPos
	// go mongodb
	MongoConnNamePos
	MongoOpNamePos
	MongoOpDBPos
	MongoOneThirteenOne
	// route harvesting offsets
	MuxTemplatePos
	GinFullpathPos
)

//go:embed offsets.json
var prefetchedOffsets string

type structInfo struct {
	// lib is the name of the library where the struct is defined.
	// "go" for the standar library or e.g. "google.golang.org/grpc"
	lib string
	// fields of the struct as key, and the name of the constant defined in the eBPF code as value
	fields map[string]GoOffset
}

// level-1 key = Struct type name and its containing library
// level-2 key = name of the field
// level-3 value = C constant name to override (e.g. path_ptr_pos)
var structMembers = map[string]structInfo{
	"net/http.Request": {
		lib: "go",
		fields: map[string]GoOffset{
			"URL":           URLPtrPos,
			"Method":        MethodPtrPos,
			"ContentLength": ContentLengthPtrPos,
			"Header":        ReqHeaderPtrPos,
		},
	},
	"net/url.URL": {
		lib: "go",
		fields: map[string]GoOffset{
			"Path":   PathPtrPos,
			"Host":   HostPtrPos,
			"Scheme": SchemePtrPos,
		},
	},
	"net/http.Response": {
		lib: "go",
		fields: map[string]GoOffset{
			"StatusCode":    StatusCodePtrPos,
			"ContentLength": ResponseLengthPtrPos,
		},
	},
	"google.golang.org/grpc/internal/transport.Stream": {
		lib: "google.golang.org/grpc",
		fields: map[string]GoOffset{
			"st":     GrpcStreamStPtrPos,
			"method": GrpcStreamMethodPtrPos,
			"id":     GrpcTransportStreamIDPos,
		},
	},
	"google.golang.org/grpc/internal/transport.ServerStream": {
		lib: "google.golang.org/grpc",
		fields: map[string]GoOffset{
			"Stream": GrpcServerStreamStream,
			"st":     GrpcServerStreamStPtr,
		},
	},
	"google.golang.org/grpc/internal/transport.ClientStream": {
		lib: "google.golang.org/grpc",
		fields: map[string]GoOffset{
			"Stream": GrpcClientStreamStream,
		},
	},
	"google.golang.org/grpc/internal/status.Status": {
		lib: "google.golang.org/grpc",
		fields: map[string]GoOffset{
			"s": GrpcStatusSPos,
		},
	},
	"google.golang.org/genproto/googleapis/rpc/status.Status": {
		lib: "google.golang.org/genproto",
		fields: map[string]GoOffset{
			"Code": GrpcStatusCodePtrPos,
		},
	},
	"google.golang.org/grpc/internal/transport.http2Server": {
		lib: "google.golang.org/grpc",
		fields: map[string]GoOffset{
			"conn": GrpcStConnPos,
		},
	},
	"net.TCPAddr": {
		lib: "go",
		fields: map[string]GoOffset{
			"IP":   TCPAddrIPPtrPos,
			"Port": TCPAddrPortPtrPos,
		},
	},
	"bufio.Writer": {
		lib: "go",
		fields: map[string]GoOffset{
			"buf": IoWriterBufPtrPos,
			"n":   IoWriterNPos,
		},
	},
	"context.valueCtx": {
		lib: "go",
		fields: map[string]GoOffset{
			"val": ValueContextValPtrPos,
		},
	},
	"google.golang.org/grpc/internal/transport.http2Client": {
		lib: "google.golang.org/grpc",
		fields: map[string]GoOffset{
			"conn":   GrpcTConnPos,
			"scheme": GrpcTSchemePos,
		},
	},
	"golang.org/x/net/http2.ClientConn": {
		lib: "golang.org/x/net",
		fields: map[string]GoOffset{
			"nextStreamID": CcNextStreamIDPos,
			"tconn":        CcTconnPos,
			"fr":           CcFramerPos,
		},
	},
	"net/http.http2Framer": {
		lib: "go",
		fields: map[string]GoOffset{
			"w": FramerWPos,
		},
	},
	"golang.org/x/net/http2.Framer": {
		lib: "golang.org/x/net",
		fields: map[string]GoOffset{
			"w": FramerWPos,
		},
	},
	"golang.org/x/net/http2.MetaHeadersFrame": {
		lib: "golang.org/x/net",
		fields: map[string]GoOffset{
			"Fields": MetaHeadersFrameFieldsPtrPos,
		},
	},
	"net/http.http2MetaHeadersFrame": {
		lib: "go",
		fields: map[string]GoOffset{
			"Fields": MetaHeadersFrameFieldsPtrPos,
		},
	},
	"golang.org/x/net/http2.serverConn": {
		lib: "golang.org/x/net",
		fields: map[string]GoOffset{
			"conn": ScConnPos,
		},
	},
	"net/http.http2ClientConn": {
		lib: "go",
		fields: map[string]GoOffset{
			"nextStreamID": CcNextStreamIDVendoredPos,
			"tconn":        CcTconnVendoredPos,
			"fr":           CcFramerVendoredPos,
		},
	},
	"net/http.http2serverConn": {
		lib: "go",
		fields: map[string]GoOffset{
			"conn": ScConnPos,
		},
	},
	"net.TCPConn": {
		lib: "go",
		fields: map[string]GoOffset{
			"conn": NetConnPos,
		},
	},
	"net.conn": {
		lib: "go",
		fields: map[string]GoOffset{
			"fd": ConnFdPos,
		},
	},
	"net.netFD": {
		lib: "go",
		fields: map[string]GoOffset{
			"laddr": FdLaddrPos,
			"raddr": FdRaddrPos,
		},
	},
	"net/http.persistConn": {
		lib: "go",
		fields: map[string]GoOffset{
			"conn":     PcConnPos,
			"tlsState": PcTLSPos,
		},
	},
	"net/http.conn": {
		lib: "go",
		fields: map[string]GoOffset{
			"rwc":      CRwcPos,
			"tlsState": CTlsPos,
		},
	},
	"net/rpc.Request": {
		lib: "go",
		fields: map[string]GoOffset{
			"ServiceMethod": GoJsonrpcRequestHeaderServiceMethodPos,
		},
	},
	"google.golang.org/grpc/internal/transport.bufWriter": {
		lib: "google.golang.org/grpc",
		fields: map[string]GoOffset{
			"buf":    GrpcTransportBufWriterBufPos,
			"offset": GrpcTransportBufWriterOffsetPos,
			"conn":   GrpcTransportBufWriterConnPos,
		},
	},
	"github.com/IBM/sarama.Broker": {
		lib: "github.com/IBM/sarama",
		fields: map[string]GoOffset{
			"correlationID": SaramaBrokerCorrIDPos,
			"conn":          SaramaBrokerConnPos,
		},
	},
	"github.com/IBM/sarama.responsePromise": {
		lib: "github.com/IBM/sarama",
		fields: map[string]GoOffset{
			"correlationID": SaramaResponseCorrIDPos,
		},
	},
	"github.com/IBM/sarama.bufConn": {
		lib: "github.com/IBM/sarama",
		fields: map[string]GoOffset{
			"Conn": SaramaBufconnConnPos,
		},
	},
	// These are duplicate because the Sarama library changed orgs,
	// from Shopify to IBM at version 1.40
	"github.com/Shopify/sarama.Broker": {
		lib: "github.com/IBM/sarama",
		fields: map[string]GoOffset{
			"correlationID": SaramaBrokerCorrIDPos,
			"conn":          SaramaBrokerConnPos,
		},
	},
	"github.com/Shopify/sarama.responsePromise": {
		lib: "github.com/IBM/sarama",
		fields: map[string]GoOffset{
			"correlationID": SaramaResponseCorrIDPos,
		},
	},
	"github.com/Shopify/sarama.bufConn": {
		lib: "github.com/IBM/sarama",
		fields: map[string]GoOffset{
			"Conn": SaramaBufconnConnPos,
		},
	},
	"github.com/redis/go-redis/v9/internal/pool.Conn": {
		lib: "github.com/redis/go-redis/v9",
		fields: map[string]GoOffset{
			"bw": RedisConnBwPos,
		},
	},
	"github.com/segmentio/kafka-go.Writer": {
		lib: "github.com/segmentio/kafka-go",
		fields: map[string]GoOffset{
			"Topic": KafkaGoWriterTopicPos,
		},
	},
	"github.com/segmentio/kafka-go/protocol.Conn": {
		lib: "github.com/segmentio/kafka-go",
		fields: map[string]GoOffset{
			"conn": KafkaGoProtocolConnPos,
		},
	},
	"github.com/segmentio/kafka-go.reader": {
		lib: "github.com/segmentio/kafka-go",
		fields: map[string]GoOffset{
			"topic": KafkaGoReaderTopicPos,
		},
	},
	"go.opentelemetry.io/otel/internal/global.tracer": {
		lib: "go.opentelemetry.io/otel",
		fields: map[string]GoOffset{
			"delegate": GoTracerDelegatePos,
		},
	},
	"go.mongodb.org/mongo-driver/mongo.Collection": {
		lib: "go.mongodb.org/mongo-driver",
		fields: map[string]GoOffset{
			"name": MongoConnNamePos,
		},
	},
	"go.mongodb.org/mongo-driver/x/mongo/driver.Operation": {
		lib: "go.mongodb.org/mongo-driver",
		fields: map[string]GoOffset{
			"Name":     MongoOpNamePos,
			"Database": MongoOpDBPos,
		},
	},
	"go.mongodb.org/mongo-driver/v2/mongo.Collection": {
		lib: "go.mongodb.org/mongo-driver",
		fields: map[string]GoOffset{
			"name": MongoConnNamePos,
		},
	},
	"go.mongodb.org/mongo-driver/v2/x/mongo/driver.Operation": {
		lib: "go.mongodb.org/mongo-driver",
		fields: map[string]GoOffset{
			"Name":     MongoOpNamePos,
			"Database": MongoOpDBPos,
		},
	},
	"github.com/gorilla/mux.routeRegexp": {
		lib: "github.com/gorilla/mux",
		fields: map[string]GoOffset{
			"template": MuxTemplatePos,
		},
	},
	"github.com/gin-gonic/gin.nodeValue": {
		lib: "github.com/gin-gonic/gin",
		fields: map[string]GoOffset{
			"fullPath": GinFullpathPos,
		},
	},
}

func structMemberOffsets(elfFile *elf.File) (FieldOffsets, error) {
	// first, try to read offsets from DWARF debug info
	var offs FieldOffsets
	var expected map[GoOffset]struct{}
	dwarfData, err := elfFile.DWARF()
	if err == nil {
		offs, expected = structMemberOffsetsFromDwarf(dwarfData)
		if len(expected) > 0 {
			log().Debug("Fields not found in the DWARF file", "fields", expected)
		} else {
			libVersions, err := findLibraryVersions(elfFile)
			if err != nil {
				return nil, fmt.Errorf("searching for library versions: %w", err)
			}
			offs = offsetsForLibVersions(offs, libVersions, log())
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

func offsetsForLibVersions(fieldOffsets FieldOffsets, libVersions map[string]string, log *slog.Logger) FieldOffsets {
	for lib, ver := range libVersions {
		switch lib {
		case "google.golang.org/grpc":
			ver = cleanLibVersion(ver, true, lib, log)

			if v, err := version.NewVersion(ver); err == nil {
				if v.GreaterThanOrEqual(grpcOneSixZero) {
					fieldOffsets[GrpcOneSixZero] = uint64(1)
				} else {
					fieldOffsets[GrpcOneSixZero] = uint64(0)
				}
				if v.GreaterThanOrEqual(grpcOneSixNine) {
					fieldOffsets[GrpcOneSixNine] = uint64(1)
				} else {
					fieldOffsets[GrpcOneSixNine] = uint64(0)
				}
			} else {
				log.Debug("can't parse version for", "library", lib)
			}
		case "go.mongodb.org/mongo-driver":
			ver = cleanLibVersion(ver, true, lib, log)

			if v, err := version.NewVersion(ver); err == nil {
				if v.GreaterThanOrEqual(mongoOneThirteenOne) {
					fieldOffsets[MongoOneThirteenOne] = uint64(1)
				} else {
					fieldOffsets[MongoOneThirteenOne] = uint64(0)
				}
			}
		}
	}

	return fieldOffsets
}

func cleanLibVersion(version string, found bool, lib string, log *slog.Logger) string {
	if !found {
		log.Debug("can't find version for library. Assuming 0.0.0", "lib", lib)
		// unversioned libraries are accounted as "0.0.0" in offsets.json file
		// https://github.com/grafana/go-offsets-tracker/blob/main/pkg/writer/writer.go#L108-L110
		return "0.0.0"
	}

	dash := strings.Index(version, "-")
	if dash > 0 {
		version = version[:dash]
	}
	return version
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
	fieldOffsets = offsetsForLibVersions(fieldOffsets, libVersions, log)
	// after putting the offsets.json in a Go structure, we search all the
	// structMembers elements on it, to get the annotated offsets
	for strName, strInfo := range structMembers {
		version, ok := libVersions[strInfo.lib]
		version = cleanLibVersion(version, ok, strInfo.lib, log)
		for fieldName, constantName := range strInfo.fields {
			// look the version of the required field in the offsets.json memory copy
			offset, ok := offs.Find(strName, fieldName, version)
			if !ok {
				log.Debug("can't find offsets for field",
					"lib", strInfo.lib, "name", strName, "field", fieldName, "version", version)
				continue
			}
			log.Debug("found offset", "fieldName", fieldName, "constantOffset", constantName, "offset", offset)
			fieldOffsets[constantName] = offset
		}
	}
	return fieldOffsets, nil
}

// structMemberOffsetsFromDwarf reads the executable dwarf information to get
// the offsets specified in the structMembers map
func structMemberOffsetsFromDwarf(data *dwarf.Data) (FieldOffsets, map[GoOffset]struct{}) {
	log := log().With("function", "structMemberOffsetsFromDwarf")
	expectedReturns := map[GoOffset]struct{}{}
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
			return fieldOffsets, expectedReturns
		}
	}
}

type dwarfReader interface {
	Next() (*dwarf.Entry, error)
}

func readMembers(
	reader dwarfReader,
	fields map[string]GoOffset,
	expectedReturns map[GoOffset]struct{},
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

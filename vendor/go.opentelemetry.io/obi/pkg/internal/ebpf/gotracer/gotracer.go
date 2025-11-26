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

package gotracer

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/config"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 Bpf ../../../../bpf/gotracer/gotracer.c -- -I../../../../bpf -DNO_HEADER_PROPAGATION
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 BpfDebug ../../../../bpf/gotracer/gotracer.c -- -I../../../../bpf -DBPF_DEBUG -DNO_HEADER_PROPAGATION
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 BpfTP ../../../../bpf/gotracer/gotracer.c -- -I../../../../bpf
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 BpfTPDebug ../../../../bpf/gotracer/gotracer.c -- -I../../../../bpf -DBPF_DEBUG

type Tracer struct {
	log                     *slog.Logger
	pidsFilter              ebpfcommon.ServiceFilter
	cfg                     *config.EBPFTracer
	metrics                 imetrics.Reporter
	bpfObjects              BpfObjects
	closers                 []io.Closer
	disabledRouteHarvesting bool
}

func New(pidFilter ebpfcommon.ServiceFilter, cfg *obi.Config, metrics imetrics.Reporter) *Tracer {
	log := slog.With("component", "go.Tracer")

	disabledRouteHarvesting := false

	for _, lang := range cfg.Discovery.DisabledRouteHarvesters {
		if strings.ToLower(lang) == "go" {
			disabledRouteHarvesting = true
			break
		}
	}

	return &Tracer{
		log:                     log,
		pidsFilter:              pidFilter,
		cfg:                     &cfg.EBPF,
		metrics:                 metrics,
		disabledRouteHarvesting: disabledRouteHarvesting,
	}
}

func (p *Tracer) AllowPID(pid, ns uint32, svc *svc.Attrs) {
	p.pidsFilter.AllowPID(pid, ns, svc, ebpfcommon.PIDTypeGo)
}

func (p *Tracer) BlockPID(pid, ns uint32) {
	p.pidsFilter.BlockPID(pid, ns)
}

func (p *Tracer) supportsContextPropagation() bool {
	return !ebpfcommon.IntegrityModeOverride && ebpfcommon.SupportsContextPropagationWithProbe(p.log)
}

func (p *Tracer) Load() (*ebpf.CollectionSpec, error) {
	loader := LoadBpf
	if p.cfg.BpfDebug {
		loader = LoadBpfDebug
	}

	if p.supportsContextPropagation() {
		loader = LoadBpfTP
		if p.cfg.BpfDebug {
			loader = LoadBpfTPDebug
		}
	} else {
		p.log.Info("Kernel in lockdown mode or missing CAP_SYS_ADMIN.")
	}
	return loader()
}

func (p *Tracer) SetupTailCalls() {
}

func (p *Tracer) Constants() map[string]any {
	blackBoxCP := uint32(0)
	if p.cfg.DisableBlackBoxCP {
		blackBoxCP = uint32(1)
	}

	return map[string]any{
		"wakeup_data_bytes":      uint32(p.cfg.WakeupLen) * uint32(unsafe.Sizeof(ebpfcommon.HTTPRequestTrace{})),
		"disable_black_box_cp":   blackBoxCP,
		"attr_type_invalid":      uint64(attribute.INVALID),
		"attr_type_bool":         uint64(attribute.BOOL),
		"attr_type_int64":        uint64(attribute.INT64),
		"attr_type_float64":      uint64(attribute.FLOAT64),
		"attr_type_string":       uint64(attribute.STRING),
		"attr_type_boolslice":    uint64(attribute.BOOLSLICE),
		"attr_type_int64slice":   uint64(attribute.INT64SLICE),
		"attr_type_float64slice": uint64(attribute.FLOAT64SLICE),
		"attr_type_stringslice":  uint64(attribute.STRINGSLICE),
	}
}

func (p *Tracer) RegisterOffsets(fileInfo *exec.FileInfo, offsets *goexec.Offsets) {
	offTable := BpfOffTableT{}
	// Set the field offsets and the logLevel for the Go BPF program in a map
	for _, field := range []goexec.GoOffset{
		goexec.ConnFdPos,
		goexec.FdLaddrPos,
		goexec.FdRaddrPos,
		goexec.TCPAddrPortPtrPos,
		goexec.TCPAddrIPPtrPos,
		// http
		goexec.URLPtrPos,
		goexec.PathPtrPos,
		goexec.HostPtrPos,
		goexec.SchemePtrPos,
		goexec.MethodPtrPos,
		goexec.StatusCodePtrPos,
		goexec.ResponseLengthPtrPos,
		goexec.ContentLengthPtrPos,
		goexec.ReqHeaderPtrPos,
		goexec.IoWriterBufPtrPos,
		goexec.IoWriterNPos,
		goexec.CcNextStreamIDPos,
		goexec.CcNextStreamIDVendoredPos,
		goexec.CcFramerPos,
		goexec.CcFramerVendoredPos,
		goexec.FramerWPos,
		goexec.PcConnPos,
		goexec.PcTLSPos,
		goexec.NetConnPos,
		goexec.CcTconnPos,
		goexec.CcTconnVendoredPos,
		goexec.ScConnPos,
		goexec.CRwcPos,
		goexec.CTlsPos,
		// grpc
		goexec.GrpcStreamStPtrPos,
		goexec.GrpcStreamMethodPtrPos,
		goexec.GrpcStatusSPos,
		goexec.GrpcStatusCodePtrPos,
		goexec.MetaHeadersFrameFieldsPtrPos,
		goexec.ValueContextValPtrPos,
		goexec.GrpcStConnPos,
		goexec.GrpcTConnPos,
		goexec.GrpcTSchemePos,
		goexec.GrpcTransportStreamIDPos,
		goexec.GrpcTransportBufWriterBufPos,
		goexec.GrpcTransportBufWriterOffsetPos,
		goexec.GrpcTransportBufWriterConnPos,
		// redis
		goexec.RedisConnBwPos,
		// kafka go
		goexec.KafkaGoWriterTopicPos,
		goexec.KafkaGoProtocolConnPos,
		goexec.KafkaGoReaderTopicPos,
		// kafka sarama
		goexec.SaramaBrokerCorrIDPos,
		goexec.SaramaResponseCorrIDPos,
		goexec.SaramaBrokerConnPos,
		goexec.SaramaBufconnConnPos,
		// grpc versioning
		goexec.GrpcOneSixZero,
		goexec.GrpcOneSixNine,
		goexec.GrpcServerStreamStream,
		goexec.GrpcServerStreamStPtr,
		goexec.GrpcClientStreamStream,
		// go manual spans
		goexec.GoTracerDelegatePos,
		// go jsonrpc
		goexec.GoJsonrpcRequestHeaderServiceMethodPos,
		// go mongodb
		goexec.MongoConnNamePos,
		goexec.MongoOpNamePos,
		goexec.MongoOpDBPos,
		goexec.MongoOneThirteenOne,
		goexec.MuxTemplatePos,
		goexec.GinFullpathPos,
	} {
		if val, ok := offsets.Field[field].(uint64); ok {
			offTable.Table[field] = val
		}
	}

	for _, iType := range []struct {
		symbol string
		field  goexec.GoOffset
	}{
		{
			symbol: "go.opentelemetry.io/otel/trace.attributeOption",
			field:  goexec.GoTracerAttributeOptOffset,
		},
		{
			symbol: "*errors.errorString",
			field:  goexec.GoErrorStringOffset,
		},
	} {
		if offset, ok := offsets.ITypes[iType.symbol]; ok {
			offTable.Table[iType.field] = offset
		}
	}

	if err := p.bpfObjects.GoOffsetsMap.Put(fileInfo.Ino, offTable); err != nil {
		p.log.Error("error setting offset in map for", "pid", fileInfo.Pid, "ino", fileInfo.Ino)
	}
}

func (p *Tracer) ProcessBinary(_ *exec.FileInfo) {}

func (p *Tracer) BpfObjects() any {
	return &p.bpfObjects
}

func (p *Tracer) AddCloser(c ...io.Closer) {
	p.closers = append(p.closers, c...)
}

func (p *Tracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc {
	m := map[string][]*ebpfcommon.ProbeDesc{
		// Go runtime
		"runtime.newproc1": {{
			Start: p.bpfObjects.ObiUprobeProcNewproc1,
			End:   p.bpfObjects.ObiUprobeProcNewproc1Ret,
		}},
		"runtime.goexit1": {{
			Start: p.bpfObjects.ObiUprobeProcGoexit1,
		}},
		// Go net/http
		"net/http.serverHandler.ServeHTTP": {{
			Start: p.bpfObjects.ObiUprobeServeHTTP,
			End:   p.bpfObjects.ObiUprobeServeHTTPReturns,
		}},
		"net/http.(*conn).readRequest": {{
			Start: p.bpfObjects.ObiUprobeReadRequestStart,
			End:   p.bpfObjects.ObiUprobeReadRequestReturns,
		}},
		// Go net/rpc/jsonrpc
		"net/rpc/jsonrpc.(*serverCodec).ReadRequestHeader": {{
			Start: p.bpfObjects.ObiUprobeJsonrpcReadRequestHeader,
			End:   p.bpfObjects.ObiUprobeJsonrpcReadRequestHeaderReturns,
		}},
		"net/textproto.(*Reader).readContinuedLineSlice": {{
			End: p.bpfObjects.ObiUprobeReadContinuedLineSliceReturns,
		}},
		"net/http.(*Transport).roundTrip": {{ // HTTP client, works with Client.Do as well as using the RoundTripper directly
			Start: p.bpfObjects.ObiUprobeRoundTrip,
			End:   p.bpfObjects.ObiUprobeRoundTripReturn,
		}},
		"golang.org/x/net/http2.(*ClientConn).roundTrip": {{ // http2 client after 0.22
			Start: p.bpfObjects.ObiUprobeHttp2RoundTrip,
			End:   p.bpfObjects.ObiUprobeRoundTripReturn, // return is the same as for http 1.1
		}},
		"golang.org/x/net/http2.(*ClientConn).RoundTrip": {{ // http2 client
			Start: p.bpfObjects.ObiUprobeHttp2RoundTrip,
			End:   p.bpfObjects.ObiUprobeRoundTripReturn, // return is the same as for http 1.1
		}},
		"net/http.(*http2ClientConn).RoundTrip": {{ // http2 client vendored in Go
			Start: p.bpfObjects.ObiUprobeHttp2RoundTrip,
			End:   p.bpfObjects.ObiUprobeRoundTripReturn, // return is the same as for http 1.1
		}},
		"golang.org/x/net/http2.(*ClientConn).writeHeaders": {{ // http2 client
			Start: p.bpfObjects.ObiUprobeHttp2WriteHeaders,
		}},
		"net/http.(*http2ClientConn).writeHeaders": {{ // http2 client vendored in Go, but used from http 1.1 transition
			Start: p.bpfObjects.ObiUprobeHttp2WriteHeadersVendored,
		}},
		"golang.org/x/net/http2.(*responseWriterState).writeHeader": {{ // http2 server request done, capture the response code
			Start: p.bpfObjects.ObiUprobeHttp2ResponseWriterStateWriteHeader,
		}},
		"net/http.(*http2responseWriterState).writeHeader": {{ // same as above, vendored in go
			Start: p.bpfObjects.ObiUprobeHttp2ResponseWriterStateWriteHeader,
		}},
		"net/http.(*response).WriteHeader": {{
			Start: p.bpfObjects.ObiUprobeHttp2ResponseWriterStateWriteHeader, // http response code capture
		}},
		"golang.org/x/net/http2.(*serverConn).runHandler": {{
			Start: p.bpfObjects.ObiUprobeHttp2serverConnRunHandler, // http2 server connection tracking
		}},
		"net/http.(*http2serverConn).runHandler": {{
			Start: p.bpfObjects.ObiUprobeHttp2serverConnRunHandler, // http2 server connection tracking, vendored in go
		}},
		"golang.org/x/net/http2.(*serverConn).processHeaders": {{
			Start: p.bpfObjects.ObiUprobeHttp2ServerProcessHeaders, // http2 server request header parsing
		}},
		"net/http.(*http2serverConn).processHeaders": {{
			Start: p.bpfObjects.ObiUprobeHttp2ServerProcessHeaders, // http2 server request header parsing, vendored in go
		}},
		// tracking of tcp connections for black-box propagation
		"net/http.(*conn).serve": {{ // http server
			Start: p.bpfObjects.ObiUprobeConnServe,
			End:   p.bpfObjects.ObiUprobeConnServeRet,
		}},
		"net.(*netFD).Read": {
			{
				Start: p.bpfObjects.ObiUprobeNetFdRead,
			},
		},
		"net/http.(*persistConn).roundTrip": {{ // http client
			Start: p.bpfObjects.ObiUprobePersistConnRoundTrip,
		}},
		// sql
		"database/sql.(*DB).queryDC": {{
			Start: p.bpfObjects.ObiUprobeQueryDC,
			End:   p.bpfObjects.ObiUprobeQueryReturn,
		}},
		"database/sql.(*DB).execDC": {{
			Start: p.bpfObjects.ObiUprobeExecDC,
			End:   p.bpfObjects.ObiUprobeQueryReturn,
		}},
		// Go gRPC
		"google.golang.org/grpc.(*Server).handleStream": {{
			Start: p.bpfObjects.ObiUprobeServerHandleStream,
			End:   p.bpfObjects.ObiUprobeServerHandleStreamReturn,
		}},
		"google.golang.org/grpc/internal/transport.(*http2Server).WriteStatus": {{
			Start: p.bpfObjects.ObiUprobeTransportWriteStatus,
		}},
		// in grpc 1.69.0 they renamed the above WriteStatus to writeStatus lowercase
		"google.golang.org/grpc/internal/transport.(*http2Server).writeStatus": {{
			Start: p.bpfObjects.ObiUprobeTransportWriteStatus,
		}},
		"google.golang.org/grpc.(*ClientConn).Invoke": {{
			Start: p.bpfObjects.ObiUprobeClientConnInvoke,
			End:   p.bpfObjects.ObiUprobeClientConnInvokeReturn,
		}},
		"google.golang.org/grpc.(*ClientConn).NewStream": {{
			Start: p.bpfObjects.ObiUprobeClientConnNewStream,
			End:   p.bpfObjects.ObiUprobeClientConnNewStreamReturn,
		}},
		"google.golang.org/grpc.(*ClientConn).Close": {{
			Start: p.bpfObjects.ObiUprobeClientConnClose,
		}},
		"google.golang.org/grpc.(*clientStream).RecvMsg": {{
			End: p.bpfObjects.ObiUprobeClientStreamRecvMsgReturn,
		}},
		"google.golang.org/grpc.(*clientStream).CloseSend": {{
			End: p.bpfObjects.ObiUprobeClientConnInvokeReturn,
		}},
		"google.golang.org/grpc/internal/transport.(*http2Client).NewStream": {{
			Start: p.bpfObjects.ObiUprobeTransportHttp2ClientNewStream,
			End:   p.bpfObjects.ObiUprobeTransportHttp2ClientNewStreamReturns,
		}},
		"google.golang.org/grpc/internal/transport.(*http2Server).operateHeaders": {{
			Start: p.bpfObjects.ObiUprobeHttp2ServerOperateHeaders,
		}},
		"google.golang.org/grpc/internal/transport.(*serverHandlerTransport).HandleStreams": {{
			Start: p.bpfObjects.ObiUprobeServerHandlerTransportHandleStreams,
		}},
		// Redis
		"github.com/redis/go-redis/v9/internal/pool.(*Conn).WithWriter": {{
			Start: p.bpfObjects.ObiUprobeRedisWithWriter,
			End:   p.bpfObjects.ObiUprobeRedisWithWriterRet,
		}},
		"github.com/redis/go-redis/v9.(*baseClient)._process": {{
			Start: p.bpfObjects.ObiUprobeRedisProcess,
			End:   p.bpfObjects.ObiUprobeRedisProcessRet,
		}},
		"github.com/redis/go-redis/v9.(*baseClient).pipelineProcessCmds": {{
			Start: p.bpfObjects.ObiUprobeRedisProcess,
			End:   p.bpfObjects.ObiUprobeRedisProcessRet,
		}},
		"github.com/redis/go-redis/v9.(*baseClient).txPipelineProcessCmds": {{
			Start: p.bpfObjects.ObiUprobeRedisProcess,
			End:   p.bpfObjects.ObiUprobeRedisProcessRet,
		}},
		// Kafka Go
		"github.com/segmentio/kafka-go.(*Writer).WriteMessages": {{ // runs on the same gorountine as other requests, finds traceparent info
			Start: p.bpfObjects.ObiUprobeWriterWriteMessages,
		}},
		"github.com/segmentio/kafka-go.(*Writer).produce": {{ // stores the current topic
			Start: p.bpfObjects.ObiUprobeWriterProduce,
		}},
		"github.com/segmentio/kafka-go.(*Client).roundTrip": {{ // has the goroutine connection with (*Writer).produce and msg* connection with protocol.RoundTrip
			Start: p.bpfObjects.ObiUprobeClientRoundTrip,
		}},
		"github.com/segmentio/kafka-go/protocol.RoundTrip": {{ // used for collecting the connection information
			Start: p.bpfObjects.ObiUprobeProtocolRoundtrip,
			End:   p.bpfObjects.ObiUprobeProtocolRoundtripRet,
		}},
		"github.com/segmentio/kafka-go.(*reader).read": {{ // used for capturing the info for the fetch operations
			Start: p.bpfObjects.ObiUprobeReaderRead,
			End:   p.bpfObjects.ObiUprobeReaderReadRet,
		}},
		"github.com/segmentio/kafka-go.(*reader).sendMessage": {{ // to accurately measure the start time
			Start: p.bpfObjects.ObiUprobeReaderSendMessage,
		}},
		// Kafka sarama
		"github.com/IBM/sarama.(*Broker).write": {{
			Start: p.bpfObjects.ObiUprobeSaramaBrokerWrite,
		}},
		"github.com/IBM/sarama.(*responsePromise).handle": {{
			Start: p.bpfObjects.ObiUprobeSaramaResponsePromiseHandle,
		}},
		"github.com/IBM/sarama.(*Broker).sendInternal": {{
			Start: p.bpfObjects.ObiUprobeSaramaSendInternal,
		}},
		"github.com/Shopify/sarama.(*Broker).write": {{
			Start: p.bpfObjects.ObiUprobeSaramaBrokerWrite,
		}},
		"github.com/Shopify/sarama.(*responsePromise).handle": {{
			Start: p.bpfObjects.ObiUprobeSaramaResponsePromiseHandle,
		}},
		"github.com/Shopify/sarama.(*Broker).sendInternal": {{
			Start: p.bpfObjects.ObiUprobeSaramaSendInternal,
		}},
		// Go OTel SDK
		"go.opentelemetry.io/otel/internal/global.(*tracer).Start": {{
			Start: p.bpfObjects.ObiUprobeTracerStartGlobal,
			End:   p.bpfObjects.ObiUprobeTracerStartReturns,
		}},
		"go.opentelemetry.io/auto/sdk.(*tracer).Start": {{
			Start: p.bpfObjects.ObiUprobeTracerStart,
			End:   p.bpfObjects.ObiUprobeTracerStartReturns,
		}},
		"go.opentelemetry.io/otel/internal/global.(*nonRecordingSpan).End": {{
			Start: p.bpfObjects.ObiUprobeNonRecordingSpanEnd,
		}},
		"go.opentelemetry.io/auto/sdk.(*span).End": {{
			Start: p.bpfObjects.ObiUprobeNonRecordingSpanEnd,
		}},
		"go.opentelemetry.io/otel/internal/global.(*nonRecordingSpan).SetStatus": {{
			Start: p.bpfObjects.ObiUprobeSetStatus,
		}},
		"go.opentelemetry.io/auto/sdk.(*span).SetStatus": {{
			Start: p.bpfObjects.ObiUprobeSetStatus,
		}},
		"go.opentelemetry.io/otel/internal/global.(*nonRecordingSpan).SetAttributes": {{
			Start: p.bpfObjects.ObiUprobeSetAttributes,
		}},
		"go.opentelemetry.io/auto/sdk.(*span).SetAttributes": {{
			Start: p.bpfObjects.ObiUprobeSetAttributes,
		}},
		"go.opentelemetry.io/otel/internal/global.(*nonRecordingSpan).SetName": {{
			Start: p.bpfObjects.ObiUprobeSetName,
		}},
		"go.opentelemetry.io/auto/sdk.(*span).SetName": {{
			Start: p.bpfObjects.ObiUprobeSetName,
		}},
		"go.opentelemetry.io/otel/internal/global.(*nonRecordingSpan).RecordError": {{
			Start: p.bpfObjects.ObiUprobeRecordError,
		}},
		"go.opentelemetry.io/auto/sdk.(*span).RecordError": {{
			Start: p.bpfObjects.ObiUprobeRecordError,
		}},
		// Go MongoDB
		"go.mongodb.org/mongo-driver/x/mongo/driver.Operation.Execute": {{
			Start: p.bpfObjects.ObiUprobeMongoOpExecute,
			End:   p.bpfObjects.ObiUprobeMongoOpExecuteRet,
		}},
		"go.mongodb.org/mongo-driver/v2/x/mongo/driver.Operation.Execute": {{
			Start: p.bpfObjects.ObiUprobeMongoOpExecute,
			End:   p.bpfObjects.ObiUprobeMongoOpExecuteRet,
		}},
		// all of these point to the same probe, we just use it to find start time and collection name
		"go.mongodb.org/mongo-driver/mongo.(*Collection).insert": {{
			Start: p.bpfObjects.ObiUprobeMongoOpInsert,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).insert": {{
			Start: p.bpfObjects.ObiUprobeMongoOpInsert,
		}},
		"go.mongodb.org/mongo-driver/mongo.(*Collection).delete": {{
			Start: p.bpfObjects.ObiUprobeMongoOpDelete,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).delete": {{
			Start: p.bpfObjects.ObiUprobeMongoOpDelete,
		}},
		"go.mongodb.org/mongo-driver/mongo.(*Collection).updateOrReplace": {{
			Start: p.bpfObjects.ObiUprobeMongoOpUpdateOrReplace,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).updateOrReplace": {{
			Start: p.bpfObjects.ObiUprobeMongoOpUpdateOrReplace,
		}},
		"go.mongodb.org/mongo-driver/mongo.(*Collection).find": {{
			Start: p.bpfObjects.ObiUprobeMongoOpFind,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).find": {{
			Start: p.bpfObjects.ObiUprobeMongoOpFind,
		}},
		"go.mongodb.org/mongo-driver/mongo.(*Collection).Find": {{
			Start: p.bpfObjects.ObiUprobeMongoOpFind,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).Find": {{
			Start: p.bpfObjects.ObiUprobeMongoOpFind,
		}},
		"go.mongodb.org/mongo-driver/mongo.(*Collection).drop": {{
			Start: p.bpfObjects.ObiUprobeMongoOpDrop,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).drop": {{
			Start: p.bpfObjects.ObiUprobeMongoOpDrop,
		}},
		"go.mongodb.org/mongo-driver/mongo.(*Collection).findAndModify": {{
			Start: p.bpfObjects.ObiUprobeMongoOpFindAndModify,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).findAndModify": {{
			Start: p.bpfObjects.ObiUprobeMongoOpFindAndModify,
		}},
		"go.mongodb.org/mongo-driver/mongo.(*Collection).Aggregate": {{
			Start: p.bpfObjects.ObiUprobeMongoOpAggregate,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).Aggregate": {{
			Start: p.bpfObjects.ObiUprobeMongoOpAggregate,
		}},
		"go.mongodb.org/mongo-driver/mongo.(*Collection).CountDocuments": {{
			Start: p.bpfObjects.ObiUprobeMongoOpCountDocuments,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).CountDocuments": {{
			Start: p.bpfObjects.ObiUprobeMongoOpCountDocuments,
		}},
		"go.mongodb.org/mongo-driver/mongo.(*Collection).EstimatedDocumentCount": {{
			Start: p.bpfObjects.ObiUprobeMongoOpEstimatedDocumentCount,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).EstimatedDocumentCount": {{
			Start: p.bpfObjects.ObiUprobeMongoOpEstimatedDocumentCount,
		}},
		"go.mongodb.org/mongo-driver/mongo.(*Collection).Distinct": {{
			Start: p.bpfObjects.ObiUprobeMongoOpDistinct,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).Distinct": {{
			Start: p.bpfObjects.ObiUprobeMongoOpDistinct,
		}},
	}

	// Route extraction
	if !p.disabledRouteHarvesting {
		// Go mux router
		m["net/http.(*ServeMux).findHandler"] = []*ebpfcommon.ProbeDesc{{
			End: p.bpfObjects.ObiUprobeFindHandlerRet,
		}}
		m["net/http.(*serveMux121).findHandler"] = []*ebpfcommon.ProbeDesc{{
			End: p.bpfObjects.ObiUprobeFindHandlerRet,
		}}
		// Gorilla mux router
		m["github.com/gorilla/mux.routeRegexpGroup.setMatch"] = []*ebpfcommon.ProbeDesc{{
			Start: p.bpfObjects.ObiUprobeMuxSetMatch,
		}}
		// Gin router
		m["github.com/gin-gonic/gin.(*node).getValue"] = []*ebpfcommon.ProbeDesc{{
			End: p.bpfObjects.ObiUprobeGinGetValueRet,
		}}
	}

	if p.supportsContextPropagation() {
		m["net/http.Header.writeSubset"] = []*ebpfcommon.ProbeDesc{{
			Start: p.bpfObjects.ObiUprobeWriteSubset, // http 1.x context propagation
		}}
		m["golang.org/x/net/http2.(*Framer).WriteHeaders"] = []*ebpfcommon.ProbeDesc{
			{ // http2 context propagation
				Start: p.bpfObjects.ObiUprobeHttp2FramerWriteHeaders,
				End:   p.bpfObjects.ObiUprobeHttp2FramerWriteHeadersReturns,
			},
			{ // for grpc
				Start: p.bpfObjects.ObiUprobeGrpcFramerWriteHeaders,
				End:   p.bpfObjects.ObiUprobeGrpcFramerWriteHeadersReturns,
			},
		}
		m["net/http.(*http2Framer).WriteHeaders"] = []*ebpfcommon.ProbeDesc{{ // http2 context propagation
			Start: p.bpfObjects.ObiUprobeHttp2FramerWriteHeaders,
			End:   p.bpfObjects.ObiUprobeHttp2FramerWriteHeadersReturns,
		}}
	}

	return m
}

func (p *Tracer) KProbes() map[string]ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) Tracepoints() map[string]ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) SocketFilters() []*ebpf.Program {
	return nil
}

func (p *Tracer) SockMsgs() []ebpfcommon.SockMsg { return nil }

func (p *Tracer) SockOps() []ebpfcommon.SockOps { return nil }

func (p *Tracer) Iters() []*ebpfcommon.Iter { return nil }

func (p *Tracer) RecordInstrumentedLib(_ uint64, _ []io.Closer) {}

func (p *Tracer) AddInstrumentedLibRef(_ uint64) {}

func (p *Tracer) UnlinkInstrumentedLib(_ uint64) {}

func (p *Tracer) AlreadyInstrumentedLib(_ uint64) bool {
	return false
}

func (p *Tracer) Run(ctx context.Context, ebpfEventContext *ebpfcommon.EBPFEventContext, eventsChan *msg.Queue[[]request.Span]) {
	ebpfcommon.SharedRingbuf(
		ebpfEventContext,
		ebpfcommon.NewEBPFParseContext(p.cfg, eventsChan, p.pidsFilter),
		p.cfg,
		p.pidsFilter,
		p.bpfObjects.Events,
		p.metrics,
	)(ctx, append(p.closers, &p.bpfObjects), eventsChan)
}

func (p *Tracer) Required() bool {
	return true
}

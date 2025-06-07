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
	"unsafe"

	"github.com/cilium/ebpf"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/config"
	ebpfcommon "github.com/grafana/beyla/v2/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/v2/pkg/internal/exec"
	"github.com/grafana/beyla/v2/pkg/internal/goexec"
	"github.com/grafana/beyla/v2/pkg/internal/imetrics"
	"github.com/grafana/beyla/v2/pkg/internal/request"
	"github.com/grafana/beyla/v2/pkg/internal/svc"
	"github.com/grafana/beyla/v2/pkg/pipe/msg"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf ../../../../bpf/gotracer/gotracer.c -- -I../../../../bpf -DNO_HEADER_PROPAGATION
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_debug ../../../../bpf/gotracer/gotracer.c -- -I../../../../bpf -DBPF_DEBUG -DNO_HEADER_PROPAGATION
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_tp ../../../../bpf/gotracer/gotracer.c -- -I../../../../bpf
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_tp_debug ../../../../bpf/gotracer/gotracer.c -- -I../../../../bpf -DBPF_DEBUG

type Tracer struct {
	log        *slog.Logger
	pidsFilter ebpfcommon.ServiceFilter
	cfg        *config.EBPFTracer
	metrics    imetrics.Reporter
	bpfObjects bpfObjects
	closers    []io.Closer
}

func New(cfg *beyla.Config, metrics imetrics.Reporter) *Tracer {
	log := slog.With("component", "go.Tracer")
	return &Tracer{
		log:        log,
		pidsFilter: ebpfcommon.CommonPIDsFilter(&cfg.Discovery),
		cfg:        &cfg.EBPF,
		metrics:    metrics,
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
	loader := loadBpf
	if p.cfg.BpfDebug {
		loader = loadBpf_debug
	}

	if p.supportsContextPropagation() {
		loader = loadBpf_tp
		if p.cfg.BpfDebug {
			loader = loadBpf_tp_debug
		}
	} else {
		p.log.Info("Kernel in lockdown mode or missing CAP_SYS_ADMIN.")
	}
	return loader()
}

func (p *Tracer) SetupTailCalls() {}

func (p *Tracer) Constants() map[string]any {
	blackBoxCP := uint32(0)
	if p.cfg.DisableBlackBoxCP {
		blackBoxCP = uint32(1)
	}

	return map[string]any{
		"wakeup_data_bytes":    uint32(p.cfg.WakeupLen) * uint32(unsafe.Sizeof(ebpfcommon.HTTPRequestTrace{})),
		"disable_black_box_cp": blackBoxCP,
	}
}

func (p *Tracer) RegisterOffsets(fileInfo *exec.FileInfo, offsets *goexec.Offsets) {
	offTable := bpfOffTableT{}
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
	} {
		if val, ok := offsets.Field[field].(uint64); ok {
			offTable.Table[field] = val
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
			Start: p.bpfObjects.BeylaUprobeProcNewproc1,
			End:   p.bpfObjects.BeylaUprobeProcNewproc1Ret,
		}},
		"runtime.goexit1": {{
			Start: p.bpfObjects.BeylaUprobeProcGoexit1,
		}},
		// Go net/http
		"net/http.serverHandler.ServeHTTP": {{
			Start: p.bpfObjects.BeylaUprobeServeHTTP,
			End:   p.bpfObjects.BeylaUprobeServeHTTPReturns,
		}},
		"net/http.(*conn).readRequest": {{
			Start: p.bpfObjects.BeylaUprobeReadRequestStart,
			End:   p.bpfObjects.BeylaUprobeReadRequestReturns,
		}},
		"net/http.(*body).Read": {{
			Start: p.bpfObjects.BeylaUprobeBodyRead,
			End:   p.bpfObjects.BeylaUprobeBodyReadReturn,
		}},
		"net/textproto.(*Reader).readContinuedLineSlice": {{
			End: p.bpfObjects.BeylaUprobeReadContinuedLineSliceReturns,
		}},
		"net/http.(*Transport).roundTrip": {{ // HTTP client, works with Client.Do as well as using the RoundTripper directly
			Start: p.bpfObjects.BeylaUprobeRoundTrip,
			End:   p.bpfObjects.BeylaUprobeRoundTripReturn,
		}},
		"golang.org/x/net/http2.(*ClientConn).roundTrip": {{ // http2 client after 0.22
			Start: p.bpfObjects.BeylaUprobeHttp2RoundTrip,
			End:   p.bpfObjects.BeylaUprobeRoundTripReturn, // return is the same as for http 1.1
		}},
		"golang.org/x/net/http2.(*ClientConn).RoundTrip": {{ // http2 client
			Start: p.bpfObjects.BeylaUprobeHttp2RoundTrip,
			End:   p.bpfObjects.BeylaUprobeRoundTripReturn, // return is the same as for http 1.1
		}},
		"net/http.(*http2ClientConn).RoundTrip": {{ // http2 client vendored in Go
			Start: p.bpfObjects.BeylaUprobeHttp2RoundTrip,
			End:   p.bpfObjects.BeylaUprobeRoundTripReturn, // return is the same as for http 1.1
		}},
		"golang.org/x/net/http2.(*ClientConn).writeHeaders": {{ // http2 client
			Start: p.bpfObjects.BeylaUprobeHttp2WriteHeaders,
		}},
		"net/http.(*http2ClientConn).writeHeaders": {{ // http2 client vendored in Go, but used from http 1.1 transition
			Start: p.bpfObjects.BeylaUprobeHttp2WriteHeadersVendored,
		}},
		"golang.org/x/net/http2.(*responseWriterState).writeHeader": {{ // http2 server request done, capture the response code
			Start: p.bpfObjects.BeylaUprobeHttp2ResponseWriterStateWriteHeader,
		}},
		"net/http.(*http2responseWriterState).writeHeader": {{ // same as above, vendored in go
			Start: p.bpfObjects.BeylaUprobeHttp2ResponseWriterStateWriteHeader,
		}},
		"net/http.(*response).WriteHeader": {{
			Start: p.bpfObjects.BeylaUprobeHttp2ResponseWriterStateWriteHeader, // http response code capture
		}},
		"golang.org/x/net/http2.(*serverConn).runHandler": {{
			Start: p.bpfObjects.BeylaUprobeHttp2serverConnRunHandler, // http2 server connection tracking
		}},
		"net/http.(*http2serverConn).runHandler": {{
			Start: p.bpfObjects.BeylaUprobeHttp2serverConnRunHandler, // http2 server connection tracking, vendored in go
		}},
		"golang.org/x/net/http2.(*serverConn).processHeaders": {{
			Start: p.bpfObjects.BeylaUprobeHttp2ServerProcessHeaders, // http2 server request header parsing
		}},
		"net/http.(*http2serverConn).processHeaders": {{
			Start: p.bpfObjects.BeylaUprobeHttp2ServerProcessHeaders, // http2 server request header parsing, vendored in go
		}},
		// tracking of tcp connections for black-box propagation
		"net/http.(*conn).serve": {{ // http server
			Start: p.bpfObjects.BeylaUprobeConnServe,
			End:   p.bpfObjects.BeylaUprobeConnServeRet,
		}},
		"net.(*netFD).Read": {
			{
				Start: p.bpfObjects.BeylaUprobeNetFdRead,
			},
		},
		"net/http.(*persistConn).roundTrip": {{ // http client
			Start: p.bpfObjects.BeylaUprobePersistConnRoundTrip,
		}},
		// sql
		"database/sql.(*DB).queryDC": {{
			Start: p.bpfObjects.BeylaUprobeQueryDC,
			End:   p.bpfObjects.BeylaUprobeQueryReturn,
		}},
		"database/sql.(*DB).execDC": {{
			Start: p.bpfObjects.BeylaUprobeExecDC,
			End:   p.bpfObjects.BeylaUprobeQueryReturn,
		}},
		// Go gRPC
		"google.golang.org/grpc.(*Server).handleStream": {{
			Start: p.bpfObjects.BeylaUprobeServerHandleStream,
			End:   p.bpfObjects.BeylaUprobeServerHandleStreamReturn,
		}},
		"google.golang.org/grpc/internal/transport.(*http2Server).WriteStatus": {{
			Start: p.bpfObjects.BeylaUprobeTransportWriteStatus,
		}},
		// in grpc 1.69.0 they renamed the above WriteStatus to writeStatus lowecase
		"google.golang.org/grpc/internal/transport.(*http2Server).writeStatus": {{
			Start: p.bpfObjects.BeylaUprobeTransportWriteStatus,
		}},
		"google.golang.org/grpc.(*ClientConn).Invoke": {{
			Start: p.bpfObjects.BeylaUprobeClientConnInvoke,
			End:   p.bpfObjects.BeylaUprobeClientConnInvokeReturn,
		}},
		"google.golang.org/grpc.(*ClientConn).NewStream": {{
			Start: p.bpfObjects.BeylaUprobeClientConnNewStream,
			End:   p.bpfObjects.BeylaUprobeClientConnNewStreamReturn,
		}},
		"google.golang.org/grpc.(*ClientConn).Close": {{
			Start: p.bpfObjects.BeylaUprobeClientConnClose,
		}},
		"google.golang.org/grpc.(*clientStream).RecvMsg": {{
			End: p.bpfObjects.BeylaUprobeClientStreamRecvMsgReturn,
		}},
		"google.golang.org/grpc.(*clientStream).CloseSend": {{
			End: p.bpfObjects.BeylaUprobeClientConnInvokeReturn,
		}},
		"google.golang.org/grpc/internal/transport.(*http2Client).NewStream": {{
			Start: p.bpfObjects.BeylaUprobeTransportHttp2ClientNewStream,
			End:   p.bpfObjects.BeylaUprobeTransportHttp2ClientNewStreamReturns,
		}},
		"google.golang.org/grpc/internal/transport.(*http2Server).operateHeaders": {{
			Start: p.bpfObjects.BeylaUprobeHttp2ServerOperateHeaders,
		}},
		"google.golang.org/grpc/internal/transport.(*serverHandlerTransport).HandleStreams": {{
			Start: p.bpfObjects.BeylaUprobeServerHandlerTransportHandleStreams,
		}},
		// Redis
		"github.com/redis/go-redis/v9/internal/pool.(*Conn).WithWriter": {{
			Start: p.bpfObjects.BeylaUprobeRedisWithWriter,
			End:   p.bpfObjects.BeylaUprobeRedisWithWriterRet,
		}},
		"github.com/redis/go-redis/v9.(*baseClient)._process": {{
			Start: p.bpfObjects.BeylaUprobeRedisProcess,
			End:   p.bpfObjects.BeylaUprobeRedisProcessRet,
		}},
		"github.com/redis/go-redis/v9.(*baseClient).pipelineProcessCmds": {{
			Start: p.bpfObjects.BeylaUprobeRedisProcess,
			End:   p.bpfObjects.BeylaUprobeRedisProcessRet,
		}},
		"github.com/redis/go-redis/v9.(*baseClient).txPipelineProcessCmds": {{
			Start: p.bpfObjects.BeylaUprobeRedisProcess,
			End:   p.bpfObjects.BeylaUprobeRedisProcessRet,
		}},
		// Kafka Go
		"github.com/segmentio/kafka-go.(*Writer).WriteMessages": {{ // runs on the same gorountine as other requests, finds traceparent info
			Start: p.bpfObjects.BeylaUprobeWriterWriteMessages,
		}},
		"github.com/segmentio/kafka-go.(*Writer).produce": {{ // stores the current topic
			Start: p.bpfObjects.BeylaUprobeWriterProduce,
		}},
		"github.com/segmentio/kafka-go.(*Client).roundTrip": {{ // has the goroutine connection with (*Writer).produce and msg* connection with protocol.RoundTrip
			Start: p.bpfObjects.BeylaUprobeClientRoundTrip,
		}},
		"github.com/segmentio/kafka-go/protocol.RoundTrip": {{ // used for collecting the connection information
			Start: p.bpfObjects.BeylaUprobeProtocolRoundtrip,
			End:   p.bpfObjects.BeylaUprobeProtocolRoundtripRet,
		}},
		"github.com/segmentio/kafka-go.(*reader).read": {{ // used for capturing the info for the fetch operations
			Start: p.bpfObjects.BeylaUprobeReaderRead,
			End:   p.bpfObjects.BeylaUprobeReaderReadRet,
		}},
		"github.com/segmentio/kafka-go.(*reader).sendMessage": {{ // to accurately measure the start time
			Start: p.bpfObjects.BeylaUprobeReaderSendMessage,
		}},
		// Kafka sarama
		"github.com/IBM/sarama.(*Broker).write": {{
			Start: p.bpfObjects.BeylaUprobeSaramaBrokerWrite,
		}},
		"github.com/IBM/sarama.(*responsePromise).handle": {{
			Start: p.bpfObjects.BeylaUprobeSaramaResponsePromiseHandle,
		}},
		"github.com/IBM/sarama.(*Broker).sendInternal": {{
			Start: p.bpfObjects.BeylaUprobeSaramaSendInternal,
		}},
		"github.com/Shopify/sarama.(*Broker).write": {{
			Start: p.bpfObjects.BeylaUprobeSaramaBrokerWrite,
		}},
		"github.com/Shopify/sarama.(*responsePromise).handle": {{
			Start: p.bpfObjects.BeylaUprobeSaramaResponsePromiseHandle,
		}},
		"github.com/Shopify/sarama.(*Broker).sendInternal": {{
			Start: p.bpfObjects.BeylaUprobeSaramaSendInternal,
		}},
	}

	if p.supportsContextPropagation() {
		m["net/http.Header.writeSubset"] = []*ebpfcommon.ProbeDesc{{
			Start: p.bpfObjects.BeylaUprobeWriteSubset, // http 1.x context propagation
		}}
		m["golang.org/x/net/http2.(*Framer).WriteHeaders"] = []*ebpfcommon.ProbeDesc{
			{ // http2 context propagation
				Start: p.bpfObjects.BeylaUprobeHttp2FramerWriteHeaders,
				End:   p.bpfObjects.BeylaUprobeHttp2FramerWriteHeadersReturns,
			},
			{ // for grpc
				Start: p.bpfObjects.BeylaUprobeGrpcFramerWriteHeaders,
				End:   p.bpfObjects.BeylaUprobeGrpcFramerWriteHeadersReturns,
			},
		}
		m["net/http.(*http2Framer).WriteHeaders"] = []*ebpfcommon.ProbeDesc{{ // http2 context propagation
			Start: p.bpfObjects.BeylaUprobeHttp2FramerWriteHeaders,
			End:   p.bpfObjects.BeylaUprobeHttp2FramerWriteHeadersReturns,
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

func (p *Tracer) RecordInstrumentedLib(_ uint64, _ []io.Closer) {}

func (p *Tracer) AddInstrumentedLibRef(_ uint64) {}

func (p *Tracer) UnlinkInstrumentedLib(_ uint64) {}

func (p *Tracer) AlreadyInstrumentedLib(_ uint64) bool {
	return false
}

func (p *Tracer) Run(ctx context.Context, eventsChan *msg.Queue[[]request.Span]) {
	ebpfcommon.SharedRingbuf(
		p.cfg,
		p.pidsFilter,
		p.bpfObjects.Events,
		p.metrics,
	)(ctx, append(p.closers, &p.bpfObjects), eventsChan)
}

func (p *Tracer) Required() bool {
	return true
}

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

	"github.com/grafana/beyla/pkg/beyla"
	"github.com/grafana/beyla/pkg/config"
	ebpfcommon "github.com/grafana/beyla/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/pkg/internal/exec"
	"github.com/grafana/beyla/pkg/internal/goexec"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf ../../../../bpf/go_tracer.c -- -I../../../../bpf/headers -DNO_HEADER_PROPAGATION
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_debug ../../../../bpf/go_tracer.c -- -I../../../../bpf/headers -DBPF_DEBUG -DNO_HEADER_PROPAGATION
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_tp ../../../../bpf/go_tracer.c -- -I../../../../bpf/headers
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_tp_debug ../../../../bpf/go_tracer.c -- -I../../../../bpf/headers -DBPF_DEBUG

type Tracer struct {
	log        *slog.Logger
	pidsFilter ebpfcommon.ServiceFilter
	cfg        *config.EPPFTracer
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
	return !ebpfcommon.IntegrityModeOverride && ebpfcommon.SupportsContextPropagation(p.log)
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
		goexec.MethodPtrPos,
		goexec.StatusCodePtrPos,
		goexec.ContentLengthPtrPos,
		goexec.ReqHeaderPtrPos,
		goexec.IoWriterBufPtrPos,
		goexec.IoWriterNPos,
		goexec.CcNextStreamIDPos,
		goexec.FramerWPos,
		goexec.PcConnPos,
		goexec.PcTLSPos,
		goexec.NetConnPos,
		goexec.CcTconnPos,
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
		goexec.HTTP2ClientNextIDPos,
		goexec.GrpcTransportBufWriterBufPos,
		goexec.GrpcTransportBufWriterOffsetPos,
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
		goexec.OperateHeadersNew,
	} {
		if val, ok := offsets.Field[field].(uint64); ok {
			offTable.Table[field] = val
		}
	}

	if err := p.bpfObjects.GoOffsetsMap.Put(fileInfo.Ino, offTable); err != nil {
		p.log.Error("error setting offset in map for", "pid", fileInfo.Pid, "ino", fileInfo.Ino)
	}
}

func (p *Tracer) BpfObjects() any {
	return &p.bpfObjects
}

func (p *Tracer) AddCloser(c ...io.Closer) {
	p.closers = append(p.closers, c...)
}

func (p *Tracer) AddModuleCloser(_ uint64, _ ...io.Closer) {
	p.log.Warn("add module closer not implemented for Go")
}

func (p *Tracer) GoProbes() []ebpfcommon.ProbeDesc {
	m := []ebpfcommon.ProbeDesc{
		// Go runtime
		{
			SymbolName: "runtime.newproc1",
			Start:      p.bpfObjects.UprobeProcNewproc1,
			End:        p.bpfObjects.UprobeProcNewproc1Ret,
		},
		{
			SymbolName: "runtime.goexit1",
			Start:      p.bpfObjects.UprobeProcGoexit1,
		},
		// Go net/http
		{
			SymbolName: "net/http.serverHandler.ServeHTTP",
			Start:      p.bpfObjects.UprobeServeHTTP,
			End:        p.bpfObjects.UprobeServeHTTPReturns,
		},
		{
			SymbolName: "net/http.(*conn).readRequest",
			Start:      p.bpfObjects.UprobeReadRequestStart,
			End:        p.bpfObjects.UprobeReadRequestReturns,
		},
		{
			SymbolName: "net/textproto.(*Reader).readContinuedLineSlice",
			End:        p.bpfObjects.UprobeReadContinuedLineSliceReturns,
		},
		{
			SymbolName: "net/http.(*Transport).roundTrip", // HTTP client, works with Client.Do as well as using the RoundTripper directly
			Start:      p.bpfObjects.UprobeRoundTrip,
			End:        p.bpfObjects.UprobeRoundTripReturn,
		},
		{
			SymbolName: "golang.org/x/net/http2.(*ClientConn).roundTrip", // http2 client after 0.22
			Start:      p.bpfObjects.UprobeHttp2RoundTrip,
			End:        p.bpfObjects.UprobeRoundTripReturn, // return is the same as for http 1.1
		},
		{
			SymbolName: "golang.org/x/net/http2.(*ClientConn).RoundTrip", // http2 client
			Start:      p.bpfObjects.UprobeHttp2RoundTrip,
			End:        p.bpfObjects.UprobeRoundTripReturn, // return is the same as for http 1.1
		},
		{
			SymbolName: "net/http.(*http2ClientConn).RoundTrip", // http2 client vendored in Go
			Start:      p.bpfObjects.UprobeHttp2RoundTrip,
			End:        p.bpfObjects.UprobeRoundTripReturn, // return is the same as for http 1.1
		},
		{
			SymbolName: "golang.org/x/net/http2.(*responseWriterState).writeHeader", // http2 server request done, capture the response code
			Start:      p.bpfObjects.UprobeHttp2ResponseWriterStateWriteHeader,
		},
		{
			SymbolName: "net/http.(*http2responseWriterState).writeHeader", // same as above, vendored in go
			Start:      p.bpfObjects.UprobeHttp2ResponseWriterStateWriteHeader,
		},
		{
			SymbolName: "net/http.(*response).WriteHeader",
			Start:      p.bpfObjects.UprobeHttp2ResponseWriterStateWriteHeader, // http response code capture
		},
		{
			SymbolName: "golang.org/x/net/http2.(*serverConn).runHandler",
			Start:      p.bpfObjects.UprobeHttp2serverConnRunHandler, // http2 server connection tracking
		},
		{
			SymbolName: "net/http.(*http2serverConn).runHandler",
			Start:      p.bpfObjects.UprobeHttp2serverConnRunHandler, // http2 server connection tracking, vendored in go
		},
		{
			SymbolName: "golang.org/x/net/http2.(*serverConn).processHeaders",
			Start:      p.bpfObjects.UprobeHttp2ServerProcessHeaders, // http2 server request header parsing
		},
		{
			SymbolName: "net/http.(*http2serverConn).processHeaders",
			Start:      p.bpfObjects.UprobeHttp2ServerProcessHeaders, // http2 server request header parsing, vendored in go
		},
		// tracking of tcp connections for black-box propagation
		{
			SymbolName: "net/http.(*conn).serve", // http server
			Start:      p.bpfObjects.UprobeConnServe,
			End:        p.bpfObjects.UprobeConnServeRet,
		},
		{
			SymbolName: "net.(*netFD).Read",
			Start:      p.bpfObjects.UprobeNetFdRead,
		},
		{
			SymbolName: "net/http.(*persistConn).roundTrip", // http client
			Start:      p.bpfObjects.UprobePersistConnRoundTrip,
		},
		// sql
		{
			SymbolName: "database/sql.(*DB).queryDC",
			Start:      p.bpfObjects.UprobeQueryDC,
			End:        p.bpfObjects.UprobeQueryReturn,
		},
		{
			SymbolName: "database/sql.(*DB).execDC",
			Start:      p.bpfObjects.UprobeExecDC,
			End:        p.bpfObjects.UprobeQueryReturn,
		},
		// Go gRPC
		{
			SymbolName: "google.golang.org/grpc.(*Server).handleStream",
			Start:      p.bpfObjects.UprobeServerHandleStream,
			End:        p.bpfObjects.UprobeServerHandleStreamReturn,
		},
		{
			SymbolName: "google.golang.org/grpc/internal/transport.(*http2Server).WriteStatus",
			Start:      p.bpfObjects.UprobeTransportWriteStatus,
		},
		{
			SymbolName: "google.golang.org/grpc.(*ClientConn).Invoke",
			Start:      p.bpfObjects.UprobeClientConnInvoke,
			End:        p.bpfObjects.UprobeClientConnInvokeReturn,
		},
		{
			SymbolName: "google.golang.org/grpc.(*ClientConn).NewStream",
			Start:      p.bpfObjects.UprobeClientConnNewStream,
			End:        p.bpfObjects.UprobeServerHandleStreamReturn,
		},
		{
			SymbolName: "google.golang.org/grpc.(*ClientConn).Close",
			Start:      p.bpfObjects.UprobeClientConnClose,
		},
		{
			SymbolName: "google.golang.org/grpc.(*clientStream).RecvMsg",
			End:        p.bpfObjects.UprobeClientStreamRecvMsgReturn,
		},
		{
			SymbolName: "google.golang.org/grpc.(*clientStream).CloseSend",
			End:        p.bpfObjects.UprobeClientConnInvokeReturn,
		},
		{
			SymbolName: "google.golang.org/grpc/internal/transport.(*http2Client).NewStream",
			Start:      p.bpfObjects.UprobeTransportHttp2ClientNewStream,
		},
		{
			SymbolName: "google.golang.org/grpc/internal/transport.(*http2Server).operateHeaders",
			Start:      p.bpfObjects.UprobeHttp2ServerOperateHeaders,
		},
		{
			SymbolName: "google.golang.org/grpc/internal/transport.(*serverHandlerTransport).HandleStreams",
			Start:      p.bpfObjects.UprobeServerHandlerTransportHandleStreams,
		},
		// Redis
		{
			SymbolName: "github.com/redis/go-redis/v9/internal/pool.(*Conn).WithWriter",
			Start:      p.bpfObjects.UprobeRedisWithWriter,
			End:        p.bpfObjects.UprobeRedisWithWriterRet,
		},
		{
			SymbolName: "github.com/redis/go-redis/v9.(*baseClient)._process",
			Start:      p.bpfObjects.UprobeRedisProcess,
			End:        p.bpfObjects.UprobeRedisProcessRet,
		},
		{
			SymbolName: "github.com/redis/go-redis/v9.(*baseClient).pipelineProcessCmds",
			Start:      p.bpfObjects.UprobeRedisProcess,
			End:        p.bpfObjects.UprobeRedisProcessRet,
		},
		{
			SymbolName: "github.com/redis/go-redis/v9.(*baseClient).txPipelineProcessCmds",
			Start:      p.bpfObjects.UprobeRedisProcess,
			End:        p.bpfObjects.UprobeRedisProcessRet,
		},
		// Kafka Go
		{
			SymbolName: "github.com/segmentio/kafka-go.(*Writer).WriteMessages", // runs on the same gorountine as other requests, finds traceparent info
			Start:      p.bpfObjects.UprobeWriterWriteMessages,
		},
		{
			SymbolName: "github.com/segmentio/kafka-go.(*Writer).produce", // stores the current topic
			Start:      p.bpfObjects.UprobeWriterProduce,
		},
		{
			SymbolName: "github.com/segmentio/kafka-go.(*Client).roundTrip", // has the goroutine connection with (*Writer).produce and msg* connection with protocol.RoundTrip
			Start:      p.bpfObjects.UprobeClientRoundTrip,
		},
		{
			SymbolName: "github.com/segmentio/kafka-go/protocol.RoundTrip", // used for collecting the connection information
			Start:      p.bpfObjects.UprobeProtocolRoundtrip,
			End:        p.bpfObjects.UprobeProtocolRoundtripRet,
		},
		{
			SymbolName: "github.com/segmentio/kafka-go.(*reader).read", // used for capturing the info for the fetch operations
			Start:      p.bpfObjects.UprobeReaderRead,
			End:        p.bpfObjects.UprobeReaderReadRet,
		},
		{
			SymbolName: "github.com/segmentio/kafka-go.(*reader).sendMessage", // to accurately measure the start time
			Start:      p.bpfObjects.UprobeReaderSendMessage,
		},
		// Kafka sarama
		{
			SymbolName: "github.com/IBM/sarama.(*Broker).write",
			Start:      p.bpfObjects.UprobeSaramaBrokerWrite,
		},
		{
			SymbolName: "github.com/IBM/sarama.(*responsePromise).handle",
			Start:      p.bpfObjects.UprobeSaramaResponsePromiseHandle,
		},
		{
			SymbolName: "github.com/IBM/sarama.(*Broker).sendInternal",
			Start:      p.bpfObjects.UprobeSaramaSendInternal,
		},
		{
			SymbolName: "github.com/Shopify/sarama.(*Broker).write",
			Start:      p.bpfObjects.UprobeSaramaBrokerWrite,
		},
		{
			SymbolName: "github.com/Shopify/sarama.(*responsePromise).handle",
			Start:      p.bpfObjects.UprobeSaramaResponsePromiseHandle,
		},
		{
			SymbolName: "github.com/Shopify/sarama.(*Broker).sendInternal",
			Start:      p.bpfObjects.UprobeSaramaSendInternal,
		},
	}

	if p.supportsContextPropagation() {
		m = append(m, ebpfcommon.ProbeDesc{
			SymbolName: "net/http.Header.writeSubset",
			Start:      p.bpfObjects.UprobeWriteSubset, // http 1.x context propagation
		})

		m = append(m, ebpfcommon.ProbeDesc{
			// http2 context propagation
			SymbolName: "golang.org/x/net/http2.(*Framer).WriteHeaders",
			Start:      p.bpfObjects.UprobeHttp2FramerWriteHeaders,
			End:        p.bpfObjects.UprobeHttp2FramerWriteHeadersReturns,
		})

		m = append(m, ebpfcommon.ProbeDesc{
			// for grpc
			SymbolName: "golang.org/x/net/http2.(*Framer).WriteHeaders",
			Start:      p.bpfObjects.UprobeGrpcFramerWriteHeaders,
			End:        p.bpfObjects.UprobeGrpcFramerWriteHeadersReturns,
		})

		m = append(m, ebpfcommon.ProbeDesc{
			// http2 context propagation
			SymbolName: "net/http.(*http2Framer).WriteHeaders",
			Start:      p.bpfObjects.UprobeHttp2FramerWriteHeaders,
			End:        p.bpfObjects.UprobeHttp2FramerWriteHeadersReturns,
		})
	}

	return m
}

func (p *Tracer) KProbes() map[string]ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) UProbes() map[string][]ebpfcommon.ProbeDesc {
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

func (p *Tracer) RecordInstrumentedLib(_ uint64) {}

func (p *Tracer) UnlinkInstrumentedLib(_ uint64) {}

func (p *Tracer) AlreadyInstrumentedLib(_ uint64) bool {
	return false
}

func (p *Tracer) SetupTC() {}

func (p *Tracer) Run(ctx context.Context, eventsChan chan<- []request.Span) {
	ebpfcommon.SharedRingbuf(
		p.cfg,
		p.pidsFilter,
		p.bpfObjects.Events,
		p.metrics,
	)(ctx, append(p.closers, &p.bpfObjects), eventsChan)
}

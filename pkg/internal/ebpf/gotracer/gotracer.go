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
			Start: p.bpfObjects.BeU_NewProc1,
			End:   p.bpfObjects.BeU_NewProc1Ret,
		}},
		"runtime.goexit1": {{
			Start: p.bpfObjects.BeU_GoExit0,
		}},
		// Go net/http
		"net/http.serverHandler.ServeHTTP": {{
			Start: p.bpfObjects.BeU_ServeHTTP,
			End:   p.bpfObjects.BeU_ServeHTTPRet,
		}},
		"net/http.(*conn).readRequest": {{
			Start: p.bpfObjects.BeU_ReadReqStart,
			End:   p.bpfObjects.BeU_ReadReqRet,
		}},
		"net/textproto.(*Reader).readContinuedLineSlice": {{
			End: p.bpfObjects.BeU_ReadContRet,
		}},
		"net/http.(*Transport).roundTrip": {{ // HTTP client, works with Client.Do as well as using the RoundTripper directly
			Start: p.bpfObjects.BeU_RoundTrip,
			End:   p.bpfObjects.BeU_RoundTripRet,
		}},
		"golang.org/x/net/http2.(*ClientConn).roundTrip": {{ // http2 client after 0.22
			Start: p.bpfObjects.BeU_HTTP2RndTrip,
			End:   p.bpfObjects.BeU_RoundTripRet, // return is the same as for http 1.1
		}},
		"golang.org/x/net/http2.(*ClientConn).RoundTrip": {{ // http2 client
			Start: p.bpfObjects.BeU_HTTP2RndTrip,
			End:   p.bpfObjects.BeU_RoundTripRet, // return is the same as for http 1.1
		}},
		"net/http.(*http2ClientConn).RoundTrip": {{ // http2 client vendored in Go
			Start: p.bpfObjects.BeU_HTTP2RndTrip,
			End:   p.bpfObjects.BeU_RoundTripRet, // return is the same as for http 1.1
		}},
		"net/http.(*http2ClientConn).roundTrip": {{ // http2 client vendored in Go
			Start: p.bpfObjects.BeU_HTTP2RTConn,
		}},
		"golang.org/x/net/http2.(*responseWriterState).writeHeader": {{ // http2 server request done, capture the response code
			Start: p.bpfObjects.BeU_HTTP2WrtHdr,
		}},
		"net/http.(*http2responseWriterState).writeHeader": {{ // same as above, vendored in go
			Start: p.bpfObjects.BeU_HTTP2WrtHdr,
		}},
		"net/http.(*response).WriteHeader": {{ // http response code capture
			Start: p.bpfObjects.BeU_HTTP2WrtHdr,
		}},
		"golang.org/x/net/http2.(*serverConn).runHandler": {{ // http2 server connection tracking
			Start: p.bpfObjects.BeU_HTTP2ConnHdl,
		}},
		"net/http.(*http2serverConn).runHandler": {{ // http2 server connection tracking, vendored in go
			Start: p.bpfObjects.BeU_HTTP2ConnHdl,
		}},
		"golang.org/x/net/http2.(*serverConn).processHeaders": {{ // http2 server request header parsing
			Start: p.bpfObjects.BeU_HTTP2SrvHdr,
		}},
		"net/http.(*http2serverConn).processHeaders": {{ // http2 server request header parsing, vendored in go
			Start: p.bpfObjects.BeU_HTTP2SrvHdr,
		}},
		// tracking of tcp connections for black-box propagation
		"net/http.(*conn).serve": {{ // http server
			Start: p.bpfObjects.BeU_ConnServe,
			End:   p.bpfObjects.BeU_ConnServeRet,
		}},
		"net.(*netFD).Read": {{
			Start: p.bpfObjects.BeU_NetFdRead,
		}},
		"net/http.(*persistConn).roundTrip": {{ // http client
			Start: p.bpfObjects.BeU_PerConnRndTrp,
		}},
		// sql
		"database/sql.(*DB).queryDC": {{
			Start: p.bpfObjects.BeU_QueryDC,
			End:   p.bpfObjects.BeU_QueryDCRet,
		}},
		"database/sql.(*DB).execDC": {{
			Start: p.bpfObjects.BeU_ExecDC,
			End:   p.bpfObjects.BeU_QueryDCRet,
		}},
		// Go gRPC
		"google.golang.org/grpc.(*Server).handleStream": {{
			Start: p.bpfObjects.BeU_SrvHdlStr,
			End:   p.bpfObjects.BeU_SrvHdlStrRet,
		}},
		"google.golang.org/grpc/internal/transport.(*http2Server).WriteStatus": {{
			Start: p.bpfObjects.BeU_TrpWrtStatus,
		}},
		"google.golang.org/grpc.(*ClientConn).Invoke": {{
			Start: p.bpfObjects.BeU_CliConnInvoke,
			End:   p.bpfObjects.BeU_CliConnInvRet,
		}},
		"google.golang.org/grpc.(*ClientConn).NewStream": {{
			Start: p.bpfObjects.BeU_CliConnNewStr,
			End:   p.bpfObjects.BeU_SrvHdlStrRet,
		}},
		"google.golang.org/grpc.(*ClientConn).Close": {{
			Start: p.bpfObjects.BeU_CliConnClose,
		}},
		"google.golang.org/grpc.(*clientStream).RecvMsg": {{
			End: p.bpfObjects.BeU_CliStrRecvRet,
		}},
		"google.golang.org/grpc.(*clientStream).CloseSend": {{
			End: p.bpfObjects.BeU_CliConnInvRet,
		}},
		"google.golang.org/grpc/internal/transport.(*http2Client).NewStream": {{
			Start: p.bpfObjects.BeU_HTTP2CliNewStr,
		}},
		"google.golang.org/grpc/internal/transport.(*http2Server).operateHeaders": {{
			Start: p.bpfObjects.BeU_HTTP2SrvOpHdr,
		}},
		"google.golang.org/grpc/internal/transport.(*serverHandlerTransport).HandleStreams": {{
			Start: p.bpfObjects.BeU_SrvHdlTrpStr,
		}},
		// Redis
		"github.com/redis/go-redis/v9/internal/pool.(*Conn).WithWriter": {{
			Start: p.bpfObjects.BeU_RedisWrtStart,
			End:   p.bpfObjects.BeU_RedisWrtRet,
		}},
		"github.com/redis/go-redis/v9.(*baseClient)._process": {{
			Start: p.bpfObjects.BeU_RedisProcess,
			End:   p.bpfObjects.BeU_RedisProcRet,
		}},
		"github.com/redis/go-redis/v9.(*baseClient).pipelineProcessCmds": {{
			Start: p.bpfObjects.BeU_RedisProcess,
			End:   p.bpfObjects.BeU_RedisProcRet,
		}},
		"github.com/redis/go-redis/v9.(*baseClient).txPipelineProcessCmds": {{
			Start: p.bpfObjects.BeU_RedisProcess,
			End:   p.bpfObjects.BeU_RedisProcRet,
		}},
		// Kafka Go
		"github.com/segmentio/kafka-go.(*Writer).WriteMessages": {{ // runs on the same gorountine as other requests, finds traceparent info
			Start: p.bpfObjects.BeU_WrtMsgStart,
		}},
		"github.com/segmentio/kafka-go.(*Writer).produce": {{ // stores the current topic
			Start: p.bpfObjects.BeU_WrtProduce,
		}},
		"github.com/segmentio/kafka-go.(*Client).roundTrip": {{ // has the goroutine connection with (*Writer).produce and msg* connection with protocol.RoundTrip
			Start: p.bpfObjects.BeU_CliRndTrip,
		}},
		"github.com/segmentio/kafka-go/protocol.RoundTrip": {{ // used for collecting the connection information
			Start: p.bpfObjects.BeU_ProtoRndTrip,
			End:   p.bpfObjects.BeU_ProtoRndTrpRet,
		}},
		"github.com/segmentio/kafka-go.(*reader).read": {{ // used for capturing the info for the fetch operations
			Start: p.bpfObjects.BeU_ReadStart,
			End:   p.bpfObjects.BeU_ReadRet,
		}},
		"github.com/segmentio/kafka-go.(*reader).sendMessage": {{ // to accurately measure the start time
			Start: p.bpfObjects.BeU_ReadSendMsg,
		}},
		// Kafka sarama
		"github.com/IBM/sarama.(*Broker).write": {{
			Start: p.bpfObjects.BeU_SaramaBrkWrt,
		}},
		"github.com/IBM/sarama.(*responsePromise).handle": {{
			Start: p.bpfObjects.BeU_SaramaRspHdl,
		}},
		"github.com/IBM/sarama.(*Broker).sendInternal": {{
			Start: p.bpfObjects.BeU_SaramaSendInt,
		}},
		"github.com/Shopify/sarama.(*Broker).write": {{
			Start: p.bpfObjects.BeU_SaramaBrkWrt,
		}},
		"github.com/Shopify/sarama.(*responsePromise).handle": {{
			Start: p.bpfObjects.BeU_SaramaRspHdl,
		}},
		"github.com/Shopify/sarama.(*Broker).sendInternal": {{
			Start: p.bpfObjects.BeU_SaramaSendInt,
		}},
	}

	if p.supportsContextPropagation() {
		m["net/http.Header.writeSubset"] = []*ebpfcommon.ProbeDesc{{ // http 1.x context propagation
			Start: p.bpfObjects.BeU_WriteSubset,
		}}
		m["golang.org/x/net/http2.(*Framer).WriteHeaders"] = []*ebpfcommon.ProbeDesc{
			{ // http2 context propagation
				Start: p.bpfObjects.BeU_HTTP2FrmWrt,
				End:   p.bpfObjects.BeU_HTTP2FrmRet,
			},
			{ // for grpc
				Start: p.bpfObjects.BeU_GRPCFrmWrtHdr,
				End:   p.bpfObjects.BeU_GRPCFrmWrtRet,
			},
		}
		m["net/http.(*http2Framer).WriteHeaders"] = []*ebpfcommon.ProbeDesc{{ // http2 context propagation
			Start: p.bpfObjects.BeU_HTTP2FrmWrt,
			End:   p.bpfObjects.BeU_HTTP2FrmRet,
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

func (p *Tracer) Run(ctx context.Context, eventsChan chan<- []request.Span) {
	ebpfcommon.SharedRingbuf(
		p.cfg,
		p.pidsFilter,
		p.bpfObjects.Events,
		p.metrics,
	)(ctx, append(p.closers, &p.bpfObjects), eventsChan)
}

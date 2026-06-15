// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"errors"
	"log/slog"
	"strconv"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
	"go.opentelemetry.io/obi/pkg/internal/sunrpcparser"
)

// SunRPCInfo carries parsed ONC RPC metadata for span creation.
type SunRPCInfo struct {
	Program     uint32
	Version     uint32
	Procedure   uint32
	ProgramName string
	Method      string
	AuthFlavor  string
	Status      int
}

var errSunRPCParseFailed = errors.New("sunrpc parse failed")

// ProcessPossibleSunRPCEvent parses both TCP capture buffers and picks the best SunRPC
// metadata for span creation. The ignore bool means drop quietly; ErrNotSunRPC means
// this event is not SunRPC.
func ProcessPossibleSunRPCEvent(event *TCPRequestInfo, pkt, rpkt *largebuf.LargeBuffer) (*SunRPCInfo, bool, error) {
	// ignore=true when a buffer is empty, not SunRPC, or inconclusive — see processSunRPCBuffer.
	reqInfo, reqIgnore, reqErr := processSunRPCBuffer(pkt)
	respInfo, respIgnore, respErr := processSunRPCBuffer(rpkt)

	reqCall := reqErr == nil && !reqIgnore && isSunRPCCallInfo(reqInfo)
	respCall := respErr == nil && !respIgnore && isSunRPCCallInfo(respInfo)

	// eBPF labels pkt/rpkt by capture direction (send vs recv), not by RPC role. When both
	// peers use ephemeral ports or OBI attaches mid-connection, the CALL may appear in rpkt.
	// We handle those edge cases by reversing the direction/addresses so the span kind stays correct.
	switch {
	case reqCall:
		mergeSunRPCReplyStatus(reqInfo, respInfo, respErr, respIgnore)
		return reqInfo, false, nil
	case respCall:
		// CALL is in rpkt, not pkt — reverse direction/addresses so span kind stays correct.
		reverseTCPEvent(event)
		mergeSunRPCReplyStatus(respInfo, reqInfo, reqErr, reqIgnore)
		return respInfo, false, nil
	case reqErr == nil && !reqIgnore && reqInfo != nil:
		// REPLY-only in the request buffer; CALL was not captured.
		return reqInfo, false, nil
	case respErr == nil && !respIgnore && respInfo != nil:
		// REPLY-only in rpkt; same buffer/direction ambiguity as respCall above.
		reverseTCPEvent(event)
		return respInfo, false, nil
	case reqErr == nil || respErr == nil:
		// Framing looked plausible but no CALL/REPLY extracted; not worth an error span.
		return nil, true, nil
	}

	if errors.Is(reqErr, sunrpcparser.ErrNotSunRPC) && errors.Is(respErr, sunrpcparser.ErrNotSunRPC) {
		return nil, true, sunrpcparser.ErrNotSunRPC
	}

	return nil, true, errSunRPCParseFailed
}

// isSunRPCCallInfo distinguishes CALL spans from REPLY-only spans (Method == SunRPCSyntheticReplyMethod).
func isSunRPCCallInfo(info *SunRPCInfo) bool {
	return info != nil && info.Method != request.SunRPCSyntheticReplyMethod
}

// mergeSunRPCReplyStatus copies accept_stat from a paired REPLY into the CALL span.
func mergeSunRPCReplyStatus(callInfo *SunRPCInfo, replyInfo *SunRPCInfo, replyErr error, replyIgnore bool) {
	if callInfo == nil || replyErr != nil || replyIgnore || replyInfo == nil {
		return
	}
	if replyInfo.Status != 0 {
		callInfo.Status = replyInfo.Status
	}
}

// processSunRPCBuffer parses one capture buffer. The ignore flag means this buffer
// contributed nothing usable: empty, not SunRPC, inconclusive parse, or parse error.
// When ignore is true, info is nil except for a successful CALL/REPLY parse (ignore=false).
func processSunRPCBuffer(pkt *largebuf.LargeBuffer) (*SunRPCInfo, bool, error) {
	if pkt == nil || pkt.IsEmpty() {
		return nil, true, sunrpcparser.ErrNotSunRPC
	}

	reader := pkt.NewReader()
	if !sunrpcparser.IsLikelySunRPC(&reader) {
		return nil, true, sunrpcparser.ErrNotSunRPC
	}

	reader.Reset()
	result, err := sunrpcparser.Parse(&reader)
	if err != nil {
		return nil, true, err
	}

	if result.Call != nil {
		return sunRPCInfoFromCall(result.Call, result.Reply), false, nil
	}

	if result.Reply != nil {
		return sunRPCInfoFromReply(result.Reply), false, nil
	}

	// Record marking matched but no complete CALL/REPLY header in this buffer.
	return nil, true, nil
}

func sunRPCInfoFromCall(call *sunrpcparser.CallInfo, reply *sunrpcparser.ReplyInfo) *SunRPCInfo {
	progName := sunrpcparser.ProgramName(call.Program)
	if progName == "" {
		progName = strconv.FormatUint(uint64(call.Program), 10)
	}

	info := &SunRPCInfo{
		Program:     call.Program,
		Version:     call.Version,
		Procedure:   call.Procedure,
		ProgramName: progName,
		Method:      sunrpcparser.ProcedureLabel(call.Program, call.Procedure),
		AuthFlavor:  sunrpcparser.AuthFlavorName(call.AuthFlavor),
	}

	if reply != nil && reply.MatchCallXid {
		info.Status = sunRPCStatusFromReply(reply)
	}

	return info
}

func sunRPCInfoFromReply(reply *sunrpcparser.ReplyInfo) *SunRPCInfo {
	info := &SunRPCInfo{
		ProgramName: "sunrpc",
		Method:      request.SunRPCSyntheticReplyMethod,
	}
	info.Status = sunRPCStatusFromReply(reply)
	return info
}

// sunRPCStatusFromReply maps REPLY outcomes to span.Status (non-zero => STATUS_CODE_ERROR).
func sunRPCStatusFromReply(reply *sunrpcparser.ReplyInfo) int {
	switch {
	case reply.Denied:
		return 1
	case reply.AcceptStat != sunrpcAcceptSuccess:
		return int(reply.AcceptStat) + 1
	}
	return 0
}

const sunrpcAcceptSuccess = 0

func TCPToSunRPCToSpan(trace *TCPRequestInfo, data *SunRPCInfo) request.Span {
	peer := ""
	hostname := ""
	peerPort := 0
	hostPort := 0

	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(&trace.ConnInfo).reqHostInfo()
		peerPort = int(trace.ConnInfo.S_port)
		hostPort = int(trace.ConnInfo.D_port)
	}

	spanType := sunRPCSpanType(trace, data)

	var subType int
	if data.Version > 0 && data.Version <= 255 {
		subType = int(data.Version)
	}

	route := ""
	if isSunRPCCallInfo(data) {
		route = strconv.FormatUint(uint64(data.Procedure), 10)
	}

	return request.Span{
		Type:         spanType,
		Method:       data.Method,
		Path:         data.ProgramName,
		Route:        route,
		Statement:    data.AuthFlavor,
		SubType:      subType,
		Peer:         peer,
		PeerPort:     peerPort,
		Host:         hostname,
		HostPort:     hostPort,
		RequestStart: int64(trace.StartMonotimeNs),
		Start:        int64(trace.StartMonotimeNs),
		End:          int64(trace.EndMonotimeNs),
		Status:       data.Status,
		TraceID:      trace.Tp.TraceId,
		SpanID:       trace.Tp.SpanId,
		ParentSpanID: trace.Tp.ParentId,
		TraceFlags:   trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   app.PID(trace.Pid.HostPid),
			UserPID:   app.PID(trace.Pid.UserPid),
			Namespace: trace.Pid.Ns,
		},
	}
}

func sunRPCSpanType(trace *TCPRequestInfo, data *SunRPCInfo) request.EventType {
	// For CALL spans, recv on server and send on client (same as NATS/MQTT/Redis).
	// When CALL came from rpkt, ProcessPossibleSunRPCEvent already reversed Direction.
	serverOnRecv := trace.Direction == directionRecv
	// Reply-only: Direction reflects the REPLY leg, not the original CALL direction.
	if !isSunRPCCallInfo(data) {
		serverOnRecv = !serverOnRecv
	}
	if serverOnRecv {
		return request.EventTypeSunRPCServer
	}
	return request.EventTypeSunRPCClient
}

func matchSunRPC(_ *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, bool, bool, error) { //nolint:unparam
	info, ignore, err := ProcessPossibleSunRPCEvent(event, requestBuffer, responseBuffer)
	if ignore && err == nil {
		return request.Span{}, true, true, nil
	}

	if err != nil {
		if errors.Is(err, sunrpcparser.ErrNotSunRPC) {
			return request.Span{}, false, false, nil
		}
		slog.Debug("SunRPC parsing failed after heuristic match, dropping event", "error", err)
		return request.Span{}, true, true, nil
	}

	if info == nil {
		return request.Span{}, true, true, nil
	}

	return TCPToSunRPCToSpan(event, info), false, true, nil
}

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"unsafe"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
)

func ReadFailedConnectIntoSpan(record *ringbuf.Record, filter ServiceFilter) (request.Span, bool, error) {
	event, err := ReinterpretCast[TCPRequestInfo](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	if !filter.ValidPID(event.Pid.UserPid, event.Pid.Ns, PIDTypeKProbes) {
		return request.Span{}, true, nil
	}

	return FailedConnectToSpan(event), false, nil
}

func FailedConnectToSpan(trace *TCPRequestInfo) request.Span {
	var (
		peer, hostname             string
		peerPort, hostPort, status int
	)

	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.ConnInfo)).reqHostInfo()
		peerPort = int(trace.ConnInfo.S_port)
		hostPort = int(trace.ConnInfo.D_port)
	}

	return request.Span{
		Type:          request.EventTypeFailedConnect,
		Method:        "",
		Path:          "",
		Peer:          peer,
		PeerPort:      peerPort,
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: int64(trace.ReqLen),
		RequestStart:  int64(trace.StartMonotimeNs),
		Start:         int64(trace.StartMonotimeNs),
		End:           int64(trace.EndMonotimeNs),
		Status:        status,
		TraceID:       trace.Tp.TraceId,
		SpanID:        trace.Tp.SpanId,
		ParentSpanID:  trace.Tp.ParentId,
		TraceFlags:    trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   trace.Pid.HostPid,
			UserPID:   trace.Pid.UserPid,
			Namespace: trace.Pid.Ns,
		},
	}
}

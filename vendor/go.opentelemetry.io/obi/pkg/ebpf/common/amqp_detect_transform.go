// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"errors"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/amqpparser"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

type AMQPInfo struct {
	Direction uint8
}

func ProcessPossibleAMQPEvent(event *TCPRequestInfo, pkt, rpkt *largebuf.LargeBuffer) ([]AMQPInfo, bool, error) {
	reqLooks, reqInfos, reqErr := processAMQPBuffer(pkt, event.Direction)
	respLooks, respInfos, respErr := processAMQPBuffer(rpkt, reverseDirection(event.Direction))

	infos := reqInfos
	infos = append(infos, respInfos...)
	if len(infos) > 0 {
		return infos, false, nil
	}

	if reqErr != nil && respErr != nil {
		return nil, true, errors.Join(reqErr, respErr)
	}
	if reqErr != nil {
		return nil, true, reqErr
	}
	if respErr != nil {
		return nil, true, respErr
	}
	if reqLooks || respLooks {
		return nil, true, nil
	}
	return nil, true, amqpparser.ErrNotAMQP
}

func processAMQPBuffer(pkt *largebuf.LargeBuffer, direction uint8) (bool, []AMQPInfo, error) {
	if pkt == nil {
		return false, nil, nil
	}

	reader := pkt.NewReader()
	result, err := amqpparser.Parse(&reader)
	if err != nil {
		if errors.Is(err, amqpparser.ErrNotAMQP) {
			return false, nil, nil
		}
		return result.LooksLikeAMQP, nil, err
	}
	if !result.LooksLikeAMQP {
		return false, nil, nil
	}

	infos := make([]AMQPInfo, 0, result.TransferCount)
	for i := 0; i < result.TransferCount; i++ {
		// Each TRANSFER maps to a span; the minimal parser only records direction, so
		// same-direction transfers can look identical until deeper AMQP fields are parsed.
		infos = append(infos, AMQPInfo{Direction: direction})
	}

	return true, infos, nil
}

func TCPToAMQPToSpan(trace *TCPRequestInfo, data AMQPInfo) request.Span {
	peer, peerPort, hostname, hostPort := amqpSpanEndpoints(trace, data.Direction)

	return request.Span{
		Type:          request.EventTypeAMQPClient,
		Method:        amqpOperation(data.Direction),
		Peer:          peer,
		PeerPort:      peerPort,
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: 0,
		RequestStart:  int64(trace.StartMonotimeNs),
		Start:         int64(trace.StartMonotimeNs),
		End:           int64(trace.EndMonotimeNs),
		Status:        0,
		TraceID:       trace.Tp.TraceId,
		SpanID:        trace.Tp.SpanId,
		ParentSpanID:  trace.Tp.ParentId,
		TraceFlags:    trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   app.PID(trace.Pid.HostPid),
			UserPID:   app.PID(trace.Pid.UserPid),
			Namespace: trace.Pid.Ns,
		},
	}
}

func amqpOperation(direction uint8) string {
	if direction == directionSend {
		return request.MessagingPublish
	}

	return request.MessagingProcess
}

func amqpSpanEndpoints(trace *TCPRequestInfo, direction uint8) (peer string, peerPort int, host string, hostPort int) {
	connInfo := trace.ConnInfo
	if trace.Direction != direction {
		connInfo = reverseTCPConnInfo(connInfo)
	}

	source, target := (*BPFConnInfo)(&connInfo).reqHostInfo()
	if direction == directionSend {
		return source, int(connInfo.S_port), target, int(connInfo.D_port)
	}
	return target, int(connInfo.D_port), source, int(connInfo.S_port)
}

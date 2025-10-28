// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"unsafe"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
)

func ReadGoSaramaRequestIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	event, err := ReinterpretCast[GoSaramaClientInfo](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	info, ignore, err := ProcessKafkaRequest(event.Buf[:], nil)

	if err == nil && !ignore {
		return GoKafkaSaramaToSpan(event, info), false, nil
	}

	return request.Span{}, true, nil // ignore if we couldn't parse it
}

func GoKafkaSaramaToSpan(event *GoSaramaClientInfo, data *KafkaInfo) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0
	if event.Conn.S_port != 0 || event.Conn.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&event.Conn)).reqHostInfo()
		hostPort = int(event.Conn.D_port)
	}

	return request.Span{
		Type:          request.EventTypeKafkaClient,
		Method:        data.Operation.String(),
		Statement:     data.ClientID,
		Path:          data.Topic,
		Peer:          peer,
		PeerPort:      int(event.Conn.S_port),
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: 0,
		RequestStart:  int64(event.StartMonotimeNs),
		Start:         int64(event.StartMonotimeNs),
		End:           int64(event.EndMonotimeNs),
		Status:        0,
		Pid: request.PidInfo{
			HostPID:   event.Pid.HostPid,
			UserPID:   event.Pid.UserPid,
			Namespace: event.Pid.Ns,
		},
	}
}

func ReadGoKafkaGoRequestIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	event, err := ReinterpretCast[GoKafkaGoClientInfo](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	peer := ""
	hostname := ""
	hostPort := 0

	if event.Conn.S_port != 0 || event.Conn.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&event.Conn)).reqHostInfo()
		hostPort = int(event.Conn.D_port)
	}

	op := Produce
	if event.Op == 1 {
		op = Fetch
	}

	return request.Span{
		Type:          request.EventTypeKafkaClient,
		Method:        op.String(),
		Statement:     "github.com/segmentio/kafka-go",
		Path:          cstr(event.Topic[:]),
		Peer:          peer,
		PeerPort:      int(event.Conn.S_port),
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: 0,
		RequestStart:  int64(event.StartMonotimeNs),
		Start:         int64(event.StartMonotimeNs),
		End:           int64(event.EndMonotimeNs),
		TraceID:       trace.TraceID(event.Tp.TraceId),
		SpanID:        trace.SpanID(event.Tp.SpanId),
		ParentSpanID:  trace.SpanID(event.Tp.ParentId),
		Status:        0,
		Pid: request.PidInfo{
			HostPID:   event.Pid.HostPid,
			UserPID:   event.Pid.UserPid,
			Namespace: event.Pid.Ns,
		},
	}, false, nil
}

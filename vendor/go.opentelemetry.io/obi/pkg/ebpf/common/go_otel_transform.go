// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"encoding/json"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
)

func ReadGoOTelEventIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	event, err := ReinterpretCast[GoOTelSpanTrace](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	name := cstr(event.SpanName.Buf[:])
	descr := cstr(event.SpanDescription.Buf[:])

	attrs := ""
	if a, err := encodedAttrs(event); err == nil {
		attrs = string(a)
	}

	return request.Span{
		Type:          request.EventTypeManualSpan,
		Method:        name,
		Statement:     attrs,
		Path:          descr,
		Peer:          "",
		PeerPort:      0,
		Host:          "",
		HostPort:      0,
		ContentLength: 0,
		RequestStart:  int64(event.StartTime),
		Start:         int64(event.StartTime),
		End:           int64(event.EndTime),
		TraceID:       trace.TraceID(event.Tp.TraceId),
		SpanID:        trace.SpanID(event.Tp.SpanId),
		ParentSpanID:  trace.SpanID(event.Tp.ParentId),
		Status:        int(event.Status),
		Pid: request.PidInfo{
			HostPID:   event.Pid.HostPid,
			UserPID:   event.Pid.UserPid,
			Namespace: event.Pid.Ns,
		},
	}, false, nil
}

func encodedAttrs(event *GoOTelSpanTrace) ([]byte, error) {
	size := int(event.SpanAttrs.ValidAttrs)
	if size == 0 {
		return nil, nil
	}
	attrs := event.SpanAttrs.Attrs[:size]
	return json.Marshal(attrs)
}

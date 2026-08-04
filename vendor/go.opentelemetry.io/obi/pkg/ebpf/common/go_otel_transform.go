// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"
	"unsafe"

	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/ebpf/timing"
)

const goAutoSpanJSONMaxLen = 16 * 1024

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
			HostPID:   app.PID(event.Pid.HostPid),
			UserPID:   app.PID(event.Pid.UserPid),
			Namespace: event.Pid.Ns,
		},
	}, false, nil
}

func ReadGoAutoSpanEventIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	if record == nil {
		return request.Span{}, true, errors.New("nil Go Auto SDK span record")
	}

	headerSize := int(unsafe.Offsetof(GoAutoSpanTrace{}.Buf))
	if len(record.RawSample) < headerSize {
		return request.Span{}, true, errors.New("invalid Go Auto SDK span record: shorter than its header")
	}

	event := (*GoAutoSpanTrace)(unsafe.Pointer(unsafe.SliceData(record.RawSample)))
	size := int(event.Size)
	if size == 0 {
		return request.Span{}, true, errors.New("invalid Go Auto SDK span payload: empty")
	}
	if size > goAutoSpanJSONMaxLen {
		return request.Span{}, true, errors.New("invalid Go Auto SDK span payload: exceeds the size limit")
	}
	if size != len(record.RawSample)-headerSize {
		return request.Span{}, true, errors.New("invalid Go Auto SDK span payload: size does not match the record")
	}

	payload := record.RawSample[headerSize:]
	span, err := readAutoSpanPayload(payload)
	if err != nil {
		return request.Span{}, true, err
	}

	span.ManualOTelJSON = bytes.Clone(payload)
	span.Pid = request.PidInfo{
		HostPID:   app.PID(event.Pid.HostPid),
		UserPID:   app.PID(event.Pid.UserPid),
		Namespace: event.Pid.Ns,
	}

	return span, false, nil
}

func readAutoSpanPayload(payload []byte) (request.Span, error) {
	var unmarshaler ptrace.JSONUnmarshaler
	traces, err := unmarshaler.UnmarshalTraces(payload)
	if err != nil {
		return request.Span{}, fmt.Errorf("invalid Go Auto SDK span payload: %w", err)
	}

	resourceSpans := traces.ResourceSpans()
	if resourceSpans.Len() != 1 {
		return request.Span{}, errors.New("invalid Go Auto SDK payload: expected exactly one resource span")
	}

	scopeSpans := resourceSpans.At(0).ScopeSpans()
	if scopeSpans.Len() != 1 {
		return request.Span{}, errors.New("invalid Go Auto SDK payload: expected exactly one scope span")
	}

	spans := scopeSpans.At(0).Spans()
	if spans.Len() != 1 {
		return request.Span{}, errors.New("invalid Go Auto SDK payload: expected exactly one span")
	}

	otelSpan := spans.At(0)
	traceID := trace.TraceID(otelSpan.TraceID())
	if !traceID.IsValid() {
		return request.Span{}, errors.New("invalid Go Auto SDK payload: invalid trace ID")
	}

	spanID := trace.SpanID(otelSpan.SpanID())
	if !spanID.IsValid() {
		return request.Span{}, errors.New("invalid Go Auto SDK payload: invalid span ID")
	}

	start := otelSpan.StartTimestamp()
	end := otelSpan.EndTimestamp()
	if start == 0 || end == 0 || end < start {
		return request.Span{}, errors.New("invalid Go Auto SDK payload: invalid span timestamps")
	}

	duration := uint64(end - start)
	if duration > math.MaxInt64 {
		return request.Span{}, errors.New("invalid Go Auto SDK span duration: too large")
	}
	if start > math.MaxInt64 || end > math.MaxInt64 {
		return request.Span{}, errors.New("invalid Go Auto SDK span timestamp: outside the supported range")
	}

	wallNow := time.Now().UnixNano()
	monoNow := int64(timing.MonoTimeNow())
	startMonotime, ok := translateAutoSpanTimestamp(int64(start), wallNow, monoNow)
	if !ok {
		return request.Span{}, errors.New("invalid Go Auto SDK span start timestamp: overflows monotonic time")
	}
	endMonotime, ok := translateAutoSpanTimestamp(int64(end), wallNow, monoNow)
	if !ok {
		return request.Span{}, errors.New("invalid Go Auto SDK span end timestamp: overflows monotonic time")
	}

	status, err := autoSpanStatus(otelSpan.Status().Code())
	if err != nil {
		return request.Span{}, err
	}

	return request.Span{
		Type:         request.EventTypeManualSpan,
		SpanKind:     trace.ValidateSpanKind(trace.SpanKind(otelSpan.Kind())),
		Method:       otelSpan.Name(),
		Path:         otelSpan.Status().Message(),
		RequestStart: startMonotime,
		Start:        startMonotime,
		End:          endMonotime,
		TraceID:      traceID,
		SpanID:       spanID,
		ParentSpanID: trace.SpanID(otelSpan.ParentSpanID()),
		TraceFlags:   uint8(otelSpan.Flags() & TPFlagSampled),
		Status:       status,
	}, nil
}

func translateAutoSpanTimestamp(timestamp, wallNow, monoNow int64) (int64, bool) {
	delta := timestamp - wallNow
	if delta > 0 && monoNow > math.MaxInt64-delta {
		return 0, false
	}
	if delta < 0 && monoNow < math.MinInt64-delta {
		return 0, false
	}
	return monoNow + delta, true
}

func autoSpanStatus(status ptrace.StatusCode) (int, error) {
	switch status {
	case ptrace.StatusCodeUnset:
		return int(codes.Unset), nil
	case ptrace.StatusCodeOk:
		return int(codes.Ok), nil
	case ptrace.StatusCodeError:
		return int(codes.Error), nil
	default:
		return 0, errors.New("invalid Go Auto SDK payload: invalid span status")
	}
}

func encodedAttrs(event *GoOTelSpanTrace) ([]byte, error) {
	size := int(event.SpanAttrs.ValidAttrs)
	if size == 0 {
		return nil, nil
	}
	attrs := event.SpanAttrs.Attrs[:size]
	return json.Marshal(attrs)
}

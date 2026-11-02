// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
	"unsafe"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/ebpf/timing"
	"go.opentelemetry.io/obi/pkg/exceptions"
)

// ExceptionPayloadDecoder fills the exception fields of an event from the
// runtime-specific payload that follows the record header.
type ExceptionPayloadDecoder func(hdr *BpfExceptionEventHeaderT, payload []byte, event *exceptions.Event) error

// exceptionPayloadDecoders holds one decoder per runtime that emits
// exception_events records.
var exceptionPayloadDecoders = map[BpfExceptionRuntime]ExceptionPayloadDecoder{}

const exceptionHeaderSize = int(unsafe.Sizeof(BpfExceptionEventHeaderT{}))

var errTruncatedExceptionRecord = errors.New("truncated exception record")

// ReadExceptionRecord decodes an exception_events record into an event for
// the logs pipeline. Records from processes that are not selected for
// exception capture are ignored.
func ReadExceptionRecord(record *ringbuf.Record, filter ServiceFilter) (exceptions.Event, bool, error) {
	var hdr BpfExceptionEventHeaderT
	if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &hdr); err != nil {
		return exceptions.Event{}, true, err
	}

	payloadEnd := exceptionHeaderSize + int(hdr.PayloadLen)
	if payloadEnd > len(record.RawSample) {
		return exceptions.Event{}, true, errTruncatedExceptionRecord
	}

	decode, ok := exceptionPayloadDecoders[BpfExceptionRuntime(hdr.Runtime)]
	if !ok {
		return exceptions.Event{}, true, fmt.Errorf("unsupported exception runtime %d", hdr.Runtime)
	}

	service, ok := exceptionService(filter, &hdr)
	if !ok || !service.Exceptions.Enabled {
		return exceptions.Event{}, true, nil
	}

	event := exceptions.Event{
		Service:           service,
		Timestamp:         timing.KernelTime(hdr.CaptureNs),
		ObservedTimestamp: time.Now(),
	}
	if exceptionHasOwner(BpfExceptionOwner(hdr.Owner)) {
		event.TraceID = trace.TraceID(hdr.Tp.TraceId)
		event.SpanID = trace.SpanID(hdr.Tp.SpanId)
		event.TraceFlags = trace.TraceFlags(hdr.Tp.Flags)
	}

	if err := decode(&hdr, record.RawSample[exceptionHeaderSize:payloadEnd], &event); err != nil {
		return exceptions.Event{}, true, err
	}

	return event, false, nil
}

func exceptionHasOwner(owner BpfExceptionOwner) bool {
	switch owner {
	case BpfExceptionOwnerK_exceptionOwnerOngoing,
		BpfExceptionOwnerK_exceptionOwnerAfterResponse,
		BpfExceptionOwnerK_exceptionOwnerThread:
		return true
	default:
		return false
	}
}

// exceptionService resolves the service of the capturing process through the
// same discovery filter that decorates spans.
func exceptionService(filter ServiceFilter, hdr *BpfExceptionEventHeaderT) (svc.Attrs, bool) {
	probe := []request.Span{{
		Pid: request.PidInfo{
			HostPID:   app.PID(hdr.Pid.HostPid),
			UserPID:   app.PID(hdr.Pid.UserPid),
			Namespace: hdr.Pid.Ns,
		},
		Start: int64(hdr.CaptureNs),
		End:   int64(hdr.CaptureNs),
	}}

	matched := filter.Filter(probe)
	if len(matched) == 0 {
		return svc.Attrs{}, false
	}

	return matched[0].Service, true
}

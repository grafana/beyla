// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strconv"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
)

// nodeSpanRecord is the JSON document serialized by the Node.js span bridge
// (pkg/internal/nodejs/spanbridge.js) and smuggled to BPF through a sentinel
// uv_fs_access path (bpf/generictracer/nodejs.c).
type nodeSpanRecord struct {
	V         int            `json:"v"`
	Name      string         `json:"name"`
	TraceID   string         `json:"tid"`
	SpanID    string         `json:"sid"`
	ParentID  string         `json:"psid"`
	ExtParent bool           `json:"extParent"`
	Kind      int            `json:"kind"`
	StartNs   string         `json:"startNs"`
	DurNs     string         `json:"durNs"`
	Status    int            `json:"status"`
	StatusMsg string         `json:"statusMsg"`
	Attrs     map[string]any `json:"attrs"`
}

// nodeSpanAttr mirrors tracesgen.SpanAttr (itself the Go mirror of the BPF
// otel_attribute_t): the JSON marshaling of a slice of these is the exact
// Statement encoding manualSpanAttributes expects for EventTypeManualSpan.
type nodeSpanAttr struct {
	ValLength uint16
	Vtype     uint8
	Reserved  uint8
	Key       [32]uint8
	Value     [128]uint8
}

// ReadNodeSpanEventIntoSpan converts a node_span_event_t into the same
// request.Span shape ReadGoOTelEventIntoSpan produces, so the Node.js manual
// spans flow through the existing EventTypeManualSpan pipeline unchanged.
//
// Timing: the BPF event carries the monotonic timestamp of the sentinel
// (which fires inside span.end()), and the JSON carries the span duration;
// both timestamps are therefore in the kernel monotonic domain the rest of
// the pipeline expects (see request.Span.Timings).
//
// Trace context: when BPF found a current request context (traces_ctx_v1,
// maintained by the fdextractor.js async-context sentinels), the span is
// re-anchored onto that trace: it inherits the request's trace ID, and spans
// without an in-bridge parent are parented under OBI's automatic server span.
func ReadNodeSpanEventIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	event, err := ReinterpretCast[NodeSpanEvent](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	plen := int(event.PayloadLen)
	if plen <= 0 || plen > len(event.Payload) {
		return request.Span{}, true, errors.New("invalid node span payload length")
	}

	var rec nodeSpanRecord
	if err := json.Unmarshal(event.Payload[:plen], &rec); err != nil {
		return request.Span{}, true, err
	}
	if rec.Name == "" {
		return request.Span{}, true, errors.New("node span without a name")
	}

	spanID, err := parseSpanID(rec.SpanID)
	if err != nil {
		return request.Span{}, true, err
	}

	// Duration is a non-negative nanosecond count from the bridge's
	// process.hrtime; parse it as a signed int64 directly (it comfortably
	// fits) to avoid an unchecked uint64->int64 narrowing.
	durNs, err := strconv.ParseInt(rec.DurNs, 10, 64)
	if err != nil || durNs < 0 {
		return request.Span{}, true, errors.New("invalid node span duration")
	}
	end := int64(event.EndKtime)
	start := end - durNs

	var traceID trace.TraceID
	var parentSpanID trace.SpanID
	if event.HasParentCtx != 0 {
		traceID = trace.TraceID(event.ParentTraceId)
		parentSpanID = trace.SpanID(event.ParentSpanId)
	} else if tid, err := parseTraceID(rec.TraceID); err == nil {
		traceID = tid
	}
	// An in-bridge parent (nested manual span) wins over the request context:
	// its own root is the one anchored to the automatic span. An EXTERNAL
	// parent (the app supplied a parent context the bridge does not own) is
	// honored only when there is no OBI request context: re-anchoring rewrites
	// the trace ID, so keeping the external parent span id would export a
	// parent reference into a different trace. In that case the span is
	// flattened under the OBI request parent instead.
	if rec.ParentID != "" && (!rec.ExtParent || event.HasParentCtx == 0) {
		if psid, err := parseSpanID(rec.ParentID); err == nil {
			parentSpanID = psid
		}
	}

	attrs := ""
	if a, err := encodedNodeAttrs(rec.Attrs); err == nil && a != nil {
		attrs = string(a)
	}

	return request.Span{
		Type:         request.EventTypeManualSpan,
		Method:       rec.Name,
		Statement:    attrs,
		Path:         rec.StatusMsg,
		RequestStart: start,
		Start:        start,
		End:          end,
		TraceID:      traceID,
		SpanID:       spanID,
		ParentSpanID: parentSpanID,
		Status:       nodeStatusToCode(rec.Status),
		Pid: request.PidInfo{
			HostPID:   app.PID(event.Pid.HostPid),
			UserPID:   app.PID(event.Pid.UserPid),
			Namespace: event.Pid.Ns,
		},
	}, false, nil
}

// nodeStatusToCode maps an OpenTelemetry JS SpanStatusCode (UNSET=0, OK=1,
// ERROR=2) to the Go `codes.Code` convention (Unset=0, Error=1, Ok=2) that
// the traces pipeline uses for EventTypeManualSpan (request.SpanStatusCode).
// The two enums assign OK and ERROR the opposite values, so a raw copy would
// invert the status.
func nodeStatusToCode(jsStatus int) int {
	switch jsStatus {
	case 1: // JS OK
		return int(codes.Ok)
	case 2: // JS ERROR
		return int(codes.Error)
	default: // JS UNSET / unknown
		return int(codes.Unset)
	}
}

func parseTraceID(s string) (trace.TraceID, error) {
	var id trace.TraceID
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(id) {
		return id, errors.New("invalid trace id")
	}
	copy(id[:], b)
	return id, nil
}

func parseSpanID(s string) (trace.SpanID, error) {
	var id trace.SpanID
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(id) {
		return id, errors.New("invalid span id")
	}
	copy(id[:], b)
	return id, nil
}

// encodedNodeAttrs converts the bridge's JSON attributes into the Statement
// encoding shared with the Go manual-span path (JSON array of SpanAttr).
func encodedNodeAttrs(in map[string]any) ([]byte, error) {
	if len(in) == 0 {
		return nil, nil
	}
	attrs := make([]nodeSpanAttr, 0, len(in))
	for k, v := range in {
		if len(attrs) == cap(attrs) {
			break
		}
		a := nodeSpanAttr{}
		copy(a.Key[:len(a.Key)-1], k) // keep NUL termination
		switch val := v.(type) {
		case bool:
			a.Vtype = uint8(attribute.BOOL)
			if val {
				a.Value[0] = 1
			}
		case float64:
			if val == math.Trunc(val) && val >= math.MinInt64 && val <= math.MaxInt64 {
				a.Vtype = uint8(attribute.INT64)
				binary.LittleEndian.PutUint64(a.Value[:8], uint64(int64(val)))
			} else {
				a.Vtype = uint8(attribute.FLOAT64)
				binary.LittleEndian.PutUint64(a.Value[:8], math.Float64bits(val))
			}
		case string:
			a.Vtype = uint8(attribute.STRING)
			n := copy(a.Value[:len(a.Value)-1], val) // keep NUL termination
			a.ValLength = uint16(n)
		default:
			continue
		}
		attrs = append(attrs, a)
	}
	if len(attrs) == 0 {
		return nil, nil
	}
	return json.Marshal(attrs)
}

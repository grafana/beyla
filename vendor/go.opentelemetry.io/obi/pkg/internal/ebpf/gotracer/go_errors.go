// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gotracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/gotracer"

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/exceptions"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
)

// goSymbols symbolizes the stacks of Go exception records. The Go tracer
// registers every process that captures exceptions.
var goSymbols = ebpfcommon.NewGoSymbolRegistry()

var (
	goExceptionFrames       = goSymbols.Frames
	goExceptionValueType    = goSymbols.PanicValueType
	goExceptionReadOnlyData = goSymbols.ReadOnlyData
)

func init() {
	ebpfcommon.RegisterExceptionPayloadDecoder(
		ebpfcommon.BpfExceptionRuntimeK_exceptionRuntimeGo,
		decodeGoErrorEvent,
	)
}

// Mirrors enum go_exception_kind in bpf/gotracer/types/errors.h
const goExceptionKindPanic = 1

// Mirrors the value-read flags in bpf/gotracer/go_errors.c.
const (
	goValueHeaderRead = 1 << 0
	goValueTailRead   = 1 << 1
	goValueScalarRead = 1 << 2
	goValueStringType = 1 << 3
)

const (
	goExceptionTypeError = "go.error"
	goExceptionTypePanic = "go.panic"
	// OTel SeverityNumber ERROR. Whether a panic kills the process is not
	// known when it is captured, so panics are not reported as FATAL.
	goExceptionSeverityError = 17
	goFramesOmitted          = "... frames omitted"
)

// decodeGoErrorEvent decodes a go_exception_payload_t. A stack that cannot be
// symbolized leaves only the panic header rather than dropping the record.
func decodeGoErrorEvent(hdr *ebpfcommon.BpfExceptionEventHeaderT, payload []byte, event *exceptions.Event) error {
	p, err := ebpfcommon.ReinterpretCast[BpfGoExceptionPayloadT](payload)
	if err != nil {
		return err
	}

	panicked := p.Kind == goExceptionKindPanic
	event.Type = goExceptionTypeError
	if panicked {
		event.Type = goExceptionTypePanic
	}
	event.SeverityNumber = goExceptionSeverityError

	if panicked {
		event.Message = goPanicMessage(app.PID(hdr.Pid.HostPid), p)
	} else {
		event.Message = attributes.SanitizeUTF8(unix.ByteSliceToString(p.Message[:]))
	}

	pcs := p.Pcs[:min(int(p.Frames), len(p.Pcs))]
	frames, err := goExceptionFrames(app.PID(hdr.Pid.HostPid), pcs)
	if err != nil {
		frames = nil
	}
	event.Stacktrace = goStacktrace(panicked, event.Message, frames, len(pcs) == len(p.Pcs))

	return nil
}

// goStacktrace writes frames as runtime.Stack does, after Go's "panic: ..."
// header for panics. capacityReached means the capture may have dropped the
// outermost frames, which holds unless the stack reached runtime.goexit.
func goStacktrace(panicked bool, message string, frames []goexec.GoFrame, capacityReached bool) string {
	var out strings.Builder
	if panicked {
		out.WriteString(strings.TrimRight("panic: "+message, " "))
		out.WriteString("\n")
	}

	complete := !capacityReached
	for _, frame := range frames {
		if frame.Function == "runtime.goexit" {
			complete = true
		}
		if !goShowFrame(frame.Function) {
			continue
		}
		if out.Len() > 0 {
			out.WriteString("\n")
		}
		fmt.Fprintf(&out, "%s(...)\n\t%s:%d", frame.Function, frame.File, frame.Line)
	}

	if !complete && len(frames) > 0 {
		out.WriteString("\n" + goFramesOmitted)
	}
	return strings.TrimSuffix(out.String(), "\n")
}

// goShowFrame applies runtime.showfuncinfo's name rule: unexported runtime
// functions are hidden from tracebacks.
func goShowFrame(function string) bool {
	if !strings.Contains(function, ".") {
		return false
	}

	name, ok := strings.CutPrefix(function, "runtime.")
	if !ok {
		return true
	}
	first, _ := utf8.DecodeRuneInString(name)
	return unicode.IsUpper(first)
}

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package customspan // import "go.opentelemetry.io/obi/pkg/internal/ebpf/customspan"

import (
	"encoding/json"
	"strconv"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
)

func (r *Runtime) readNodeSpan(record *ringbuf.Record) (request.Span, bool, bool, error) {
	event, err := ebpfcommon.ReinterpretCast[ebpfcommon.BpfNodeDynamicSpanEventT](record.RawSample)
	if err != nil {
		return request.Span{}, false, true, err
	}
	def, found := r.registry.Lookup(event.Cookie)
	if !found {
		return request.Span{}, false, true, nil
	}
	span, ignore, err := ebpfcommon.ReadNodeSpanEventIntoSpan(record)
	if ignore || err != nil {
		return request.Span{}, false, true, err
	}
	var payload struct {
		Attrs map[string]string `json:"attrs"`
	}
	if err := json.Unmarshal(event.Span.Payload[:event.Span.PayloadLen], &payload); err != nil {
		return request.Span{}, false, true, err
	}
	attrs := make(map[string]string, len(payload.Attrs)+2)
	for _, slot := range def.usedSlots {
		name := "arg" + strconv.Itoa(int(slot.ArgIdx))
		if slot.Return {
			name = "return0"
			if slot.ArgIdx == 1 {
				name = "exception.message"
			}
		}
		if value, ok := payload.Attrs[name]; ok {
			attrs[slot.Name] = value
		}
	}
	if def.ProbeID != "" {
		attrs["probe.id"] = def.ProbeID
		attrs["probe.generation"] = strconv.FormatUint(def.Generation, 10)
	}
	span.TraceFlags = event.TraceFlags
	span.Type = request.EventTypeCustomSpan
	span.Method = def.Name
	span.Statement = ""
	span.CustomSpan = &request.CustomSpan{Name: def.Name, Attrs: attrs}
	return span, true, true, nil
}

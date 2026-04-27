// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// StatGetters returns the attributes.Getter function that returns the string value of a given
// attribute name.
//
//nolint:cyclop
func StatGetters(name attr.Name) (attributes.Getter[*Stat, attribute.KeyValue], bool) {
	var getter attributes.Getter[*Stat, attribute.KeyValue]
	switch name {
	case attr.OBIIP:
		getter = func(s *Stat) attribute.KeyValue { return attribute.String(string(attr.OBIIP), s.CommonAttrs.OBIIP) }
	case attr.SrcAddress:
		getter = func(s *Stat) attribute.KeyValue {
			return attribute.String(string(attr.SrcAddress), s.CommonAttrs.SrcAddr.IP().String())
		}
	case attr.DstAddress:
		getter = func(s *Stat) attribute.KeyValue {
			return attribute.String(string(attr.DstAddress), s.CommonAttrs.DstAddr.IP().String())
		}
	case attr.SrcPort:
		getter = func(s *Stat) attribute.KeyValue {
			return attribute.Int(string(attr.SrcPort), int(s.CommonAttrs.SrcPort))
		}
	case attr.DstPort:
		getter = func(s *Stat) attribute.KeyValue {
			return attribute.Int(string(attr.DstPort), int(s.CommonAttrs.DstPort))
		}
	case attr.SrcName:
		getter = func(s *Stat) attribute.KeyValue { return attribute.String(string(attr.SrcName), s.CommonAttrs.SrcName) }
	case attr.DstName:
		getter = func(s *Stat) attribute.KeyValue { return attribute.String(string(attr.DstName), s.CommonAttrs.DstName) }
	case attr.SrcZone:
		getter = func(s *Stat) attribute.KeyValue { return attribute.String(string(attr.SrcZone), s.CommonAttrs.SrcZone) }
	case attr.DstZone:
		getter = func(s *Stat) attribute.KeyValue { return attribute.String(string(attr.DstZone), s.CommonAttrs.DstZone) }
	case attr.TCPFailedConnectionReason:
		getter = func(s *Stat) attribute.KeyValue {
			if s.TCPFailedConnection == nil {
				return attribute.String(string(attr.TCPFailedConnectionReason), string(Unknown))
			}
			return attribute.String(string(attr.TCPFailedConnectionReason), tcpFailReasonStr(s.TCPFailedConnection.Reason))
		}
	default:
		getter = func(s *Stat) attribute.KeyValue { return attribute.String(string(name), s.CommonAttrs.Metadata[name]) }
	}
	return getter, getter != nil
}

func StatStringGetters(name attr.Name) (attributes.Getter[*Stat, string], bool) {
	if g, ok := StatGetters(name); ok {
		return func(s *Stat) string { return g(s).Value.Emit() }, true
	}
	return nil, false
}

func tcpFailReasonStr(reason uint8) string {
	switch TCPFailReasonTypeCode(reason) {
	case CodeConnectionRefused:
		return string(ConnectionRefused)
	case CodeConnectionReset:
		return string(ConnectionReset)
	case CodeTimedOut:
		return string(TimedOut)
	case CodeHostUnreachable:
		return string(HostUnreachable)
	case CodeNetUnreachable:
		return string(NetUnreachable)
	case CodeOther:
		return string(Other)
	default:
		return string(Unknown)
	}
}

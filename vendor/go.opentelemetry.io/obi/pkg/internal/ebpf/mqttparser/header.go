// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package mqttparser // import "go.opentelemetry.io/obi/pkg/internal/ebpf/mqttparser"

import (
	"errors"
)

const (
	MinPacketLen = 2 // fixed header (1 byte) + remaining length (1 byte)
)

type (
	// PacketType is the type of MQTT Control Packet.
	PacketType uint8

	// Offset is the position in the packet or segment.
	Offset = int
)

// MQTTControlPacket represents a parsed MQTT Control Packet's fixed header.
// Data, including variable header and payload, are to be parsed separately.
type MQTTControlPacket struct {
	FixedHeader FixedHeader
}

// Length returns the total length of the packet.
func (p MQTTControlPacket) Length() int {
	return p.FixedHeader.Length + p.FixedHeader.RemainingLength
}

// MQTT Control Packet Types, 0 is reserved.
const (
	PacketTypeCONNECT     PacketType = 1
	PacketTypeCONNACK     PacketType = 2
	PacketTypePUBLISH     PacketType = 3
	PacketTypePUBACK      PacketType = 4
	PacketTypePUBREC      PacketType = 5 // Publish received (assured delivery part 1)
	PacketTypePUBREL      PacketType = 6 // Publish release (assured delivery part 2)
	PacketTypePUBCOMP     PacketType = 7 // Publish complete (assured delivery part 3)
	PacketTypeSUBSCRIBE   PacketType = 8
	PacketTypeSUBACK      PacketType = 9
	PacketTypeUNSUBSCRIBE PacketType = 10
	PacketTypeUNSUBACK    PacketType = 11
	PacketTypePINGREQ     PacketType = 12
	PacketTypePINGRESP    PacketType = 13
	PacketTypeDISCONNECT  PacketType = 14
	PacketTypeAUTH        PacketType = 15 // MQTT 5.0 only
)

// FixedHeader, present in all MQTT Control Packets.
type FixedHeader struct {
	PacketType PacketType

	// Flags specific to each MQTT Control Packet type, particularly for PUBLISH packets.
	Flags uint8

	// RemainingLength of the packet (Variable Header + Payload).
	RemainingLength int

	// Length of fixed header:
	// 1 byte for type/flags + 1-4 bytes to represent RemainingLength.
	Length int
}

// ParseMQTTPackets parses multiple MQTT packets from a single byte slice, as
// there may be cases where multiple MQTT packets are present in one TCP segment.
func ParseMQTTPackets(segment []byte) ([]MQTTControlPacket, error) {
	var packets []MQTTControlPacket
	offset := 0

	for offset < len(segment) {
		if len(segment[offset:]) < MinPacketLen {
			break
		}

		packet, err := NewMQTTControlPacket(segment[offset:])
		if err != nil {
			return packets, err
		}

		if offset+packet.Length() > len(segment) {
			return packets, errors.New("incomplete packet")
		}

		packets = append(packets, packet)
		offset += packet.Length()
	}

	return packets, nil
}

// NewMQTTControlPacket parses the MQTT fixed header from a packet.
func NewMQTTControlPacket(pkt []byte) (MQTTControlPacket, error) {
	if len(pkt) < MinPacketLen {
		return MQTTControlPacket{}, errors.New("packet too short for MQTT fixed header")
	}

	// Parse first byte: packet type (bits 7-4) and flags (bits 3-0)
	firstByte := pkt[0]
	packetType := PacketType((firstByte >> 4) & 0x0F)
	flags := firstByte & 0x0F

	// Validate packet type (0 is reserved, valid range is 1-15)
	if packetType < PacketTypeCONNECT || packetType > PacketTypeAUTH {
		return MQTTControlPacket{}, errors.New("invalid MQTT packet type")
	}

	// Parse remaining length (variable-length encoding)
	r := NewPacketReader(pkt, 1)
	rl, err := r.ReadVariableByteInteger()
	if err != nil {
		return MQTTControlPacket{}, err
	}

	return MQTTControlPacket{
		FixedHeader: FixedHeader{
			PacketType:      packetType,
			Flags:           flags,
			RemainingLength: rl,
			Length:          r.Offset(), // 1 byte for type/flags + variable length bytes
		},
	}, nil
}

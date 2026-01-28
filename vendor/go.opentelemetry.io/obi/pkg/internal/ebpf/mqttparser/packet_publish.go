// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package mqttparser // import "go.opentelemetry.io/obi/pkg/internal/ebpf/mqttparser"

import (
	"errors"
)

// PublishPacket represents a parsed MQTT PUBLISH packet.
//
// PUBLISH packets carry application messages from publishers to subscribers.
// The packet contains a topic name and QoS level.
type PublishPacket struct {
	// Dup is true if this is a duplicate delivery (retransmission).
	Dup bool

	QoS QoSLevel

	// Retain indicates if the server should retain this message for future subscribers.
	Retain bool

	// TopicName is the topic to which the message is published.
	TopicName string

	// PacketID is present for QoS levels 1 and 2 only, used for message acknowledgment.
	PacketID uint16
}

// ParsePublishPacket parses an MQTT PUBLISH packet.
// offset should point to the start of the variable header (after fixed header).
// flags should contain the flags byte from the fixed header.
func ParsePublishPacket(pkt []byte, offset Offset, flags uint8) (*PublishPacket, Offset, error) {
	var publish PublishPacket

	if offset >= len(pkt) {
		return &publish, offset, errors.New("insufficient data for PUBLISH packet")
	}

	r := NewPublishPacketReader(pkt, offset)

	// Parse flags from fixed header
	publish.Dup = (flags & 0x08) != 0           // Bit 3: DUP flag
	publish.QoS = QoSLevel((flags & 0x06) >> 1) // Bits 2-1: QoS level
	publish.Retain = (flags & 0x01) != 0        // Bit 0: RETAIN flag

	topicName, err := r.ReadTopicName()
	if err != nil {
		return &publish, r.Offset(), err
	}
	publish.TopicName = topicName

	// Packet Identifier is present for QoS > 0
	switch publish.QoS {
	case QoSAtLeastOnce:
		fallthrough
	case QoSExactlyOnce:
		packetID, err := r.ReadPacketID()
		if err != nil {
			return &publish, r.Offset(), err
		}
		publish.PacketID = packetID
	}

	// N.B. context propagation for MQTT:
	// - MQTT 5.0, properties could be parsed here
	// - MQTT 3.1, propagation would need to go through the payload - but would
	//   likely need to be careful with performance implications.
	return &publish, r.Offset(), nil
}

// PublishPacketReader provides domain-specific read methods for PUBLISH packets.
// It embeds PacketReader to inherit primitive read operations.
type PublishPacketReader struct {
	PacketReader
}

// NewPublishPacketReader creates a new PublishPacketReader starting at the given offset.
func NewPublishPacketReader(pkt []byte, offset int) *PublishPacketReader {
	return &PublishPacketReader{PacketReader: NewPacketReader(pkt, offset)}
}

// ReadTopicName reads the topic name from the PUBLISH packet variable header.
func (r *PublishPacketReader) ReadTopicName() (string, error) {
	return r.ReadString()
}

// ReadPacketID reads the packet identifier from the PUBLISH packet variable header.
// Packet ID is present only for QoS levels 1 and 2.
func (r *PublishPacketReader) ReadPacketID() (uint16, error) {
	return r.ReadUint16()
}

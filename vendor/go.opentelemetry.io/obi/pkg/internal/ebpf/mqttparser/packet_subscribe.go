// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package mqttparser // import "go.opentelemetry.io/obi/pkg/internal/ebpf/mqttparser"

import (
	"errors"
)

// Subscription represents a single topic subscription with its QoS level.
type Subscription struct {
	// TopicFilter is the topic filter string for the subscription.
	// May include wildcards (+ and #).
	TopicFilter string

	// QoS is the maximum QoS level at which the server can send Application
	// Messages to the client.
	QoS QoSLevel
}

// SubscribePacket represents a parsed MQTT SUBSCRIBE packet.
//
// The SUBSCRIBE packet is sent from the Client to the Server.
type SubscribePacket struct {
	// PacketID is the Packet Identifier used to correlate with SUBACK response.
	PacketID uint16

	// Subscriptions contains the list of topic subscriptions.
	Subscriptions []Subscription
}

// ParseSubscribePacket parses an MQTT SUBSCRIBE packet.
// offset should point to the start of the variable header (after fixed header).
// remainingLength from the fixed header.
//
// Since OBI is stateless and the protocol version is only communicated in
// CONNECT packets, this parser uses streaming validation to detect the protocol:
//   - First attempts MQTT 3.1.1 parsing (no properties)
//   - If validation fails (e.g., invalid QoS byte), MQTT 5.0 is attempted
func ParseSubscribePacket(pkt []byte, offset Offset, remainingLength int) (*SubscribePacket, Offset, error) {
	var subscribe SubscribePacket

	if offset+remainingLength > len(pkt) {
		return &subscribe, offset, errors.New("insufficient data for SUBSCRIBE packet")
	}

	// Create a bounded slice to prevent reading beyond this packet
	// (important when multiple MQTT packets exist in one TCP segment)
	boundedPkt := pkt[:offset+remainingLength]
	r := NewSubscribePacketReader(boundedPkt, offset)

	packetID, err := r.ReadPacketID()
	if err != nil {
		return &subscribe, r.Offset(), err
	}
	subscribe.PacketID = packetID

	// Checkpoint: save offset right after PacketID - used for version detection
	checkpoint := r.Offset()

	// Attempt MQTT 3.1.1 parsing
	subscriptions, err := r.readSubscriptions(ProtocolLevelMQTT311)
	if err == nil {
		subscribe.Subscriptions = subscriptions
		return &subscribe, r.Offset(), nil
	}

	if !errors.Is(err, ErrProtocolMismatch) {
		return &subscribe, r.Offset(), err
	}

	// Protocol mismatch detected - restore to checkpoint and try MQTT 5.0
	r.SetOffset(checkpoint)

	// MQTT 5.0: Skip properties field
	if err := r.SkipProperties(); err != nil {
		return &subscribe, r.Offset(), err
	}

	subscriptions, err = r.readSubscriptions(ProtocolLevelMQTT50)
	if err != nil {
		return &subscribe, r.Offset(), err
	}
	subscribe.Subscriptions = subscriptions

	return &subscribe, r.Offset(), nil
}

// SubscribePacketReader provides domain-specific read methods for SUBSCRIBE packets.
// It embeds PacketReader to inherit primitive read operations.
type SubscribePacketReader struct {
	PacketReader
}

// NewSubscribePacketReader creates a new SubscribePacketReader starting at the given offset.
func NewSubscribePacketReader(pkt []byte, offset int) *SubscribePacketReader {
	return &SubscribePacketReader{PacketReader: NewPacketReader(pkt, offset)}
}

// ReadPacketID reads the packet identifier from the SUBSCRIBE packet variable header.
func (r *SubscribePacketReader) ReadPacketID() (uint16, error) {
	return r.ReadUint16()
}

// SkipProperties reads the property length and skips over the properties bytes.
// This is used for MQTT 5.0 packets.
func (r *SubscribePacketReader) SkipProperties() error {
	propLen, err := r.ReadVariableByteInteger()
	if err != nil {
		return err
	}
	return r.Skip(propLen)
}

// readSubscriptions reads topic filter subscriptions from the SUBSCRIBE packet payload.
//
// For MQTT 3.1.1 (targetVersion < 5):
//   - The options byte must be 0, 1, or 2 (QoS only, no additional flags)
//   - Values > 2 return ErrProtocolMismatch to trigger fallback to 5.0 parsing
//   - Failure to read the first subscription also returns ErrProtocolMismatch,
//     as this often indicates we're misinterpreting 5.0 properties as topic data
//
// For MQTT 5.0, QoS is extracted from bits 0-1, allowing for additional
// subscription option flags in the higher bits.
func (r *SubscribePacketReader) readSubscriptions(targetVersion ProtocolLevel) ([]Subscription, error) {
	var subscriptions []Subscription

	for r.Remaining() > 0 {
		topicFilter, err := r.ReadString()
		if err != nil {
			if len(subscriptions) > 0 {
				return subscriptions, nil
			}
			// In 3.1.1 mode, failure to read even the first subscription suggests
			// we might be misinterpreting MQTT 5.0 properties as topic data
			if targetVersion < ProtocolLevelMQTT50 {
				return nil, ErrProtocolMismatch
			}
			return nil, errors.New("failed to read topic filter")
		}

		options, err := r.ReadUint8()
		if err != nil {
			if len(subscriptions) > 0 {
				return subscriptions, nil
			}
			if targetVersion < ProtocolLevelMQTT50 {
				return nil, ErrProtocolMismatch
			}
			return nil, errors.New("failed to read subscription options")
		}

		// In MQTT 3.1.1, options byte contains only QoS (0, 1, or 2).
		// In MQTT 5.0, options byte has QoS in bits 0-1 plus additional flags.
		if targetVersion < ProtocolLevelMQTT50 && options > 0x02 {
			return nil, ErrProtocolMismatch
		}

		subscriptions = append(subscriptions, Subscription{
			TopicFilter: topicFilter,
			QoS:         QoSLevel(options & 0x03),
		})
	}

	if len(subscriptions) == 0 {
		if targetVersion < ProtocolLevelMQTT50 {
			return nil, ErrProtocolMismatch
		}
		return nil, errors.New("SUBSCRIBE packet must contain at least one subscription")
	}

	return subscriptions, nil
}

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package mqttparser // import "go.opentelemetry.io/obi/pkg/internal/ebpf/mqttparser"

import (
	"errors"
	"fmt"
)

// ConnectPacket represents a parsed MQTT CONNECT packet.
//
// After a Network Connection is established by a Client to a Server, the first
// packet sent from the Client to the Server MUST be a CONNECT packet.
//
// A Client can only send the CONNECT packet once over a Network Connection.
//
// The Payload contains one or more encoded fields. They specify a unique Client
// identifier for the Client, a Will Topic, Will Payload, User Name and
// Password. All but the Client identifier can be omitted and their presence is
// determined based on flags in the Variable Header.
type ConnectPacket struct {
	Protocol Protocol

	// CleanStart is a flag that indicates if the client should create a new session.
	CleanStart bool

	// KeepAlive is the maximum time in seconds between messages.
	KeepAlive uint16

	// ClientID is a required field in the CONNECT packet payload.
	ClientID string
}

// ParseConnectPacket parses an MQTT CONNECT packet.
// offset should point to the start of the variable header (after fixed header).
func ParseConnectPacket(pkt []byte, offset Offset) (*ConnectPacket, Offset, error) {
	var connect ConnectPacket

	if offset >= len(pkt) {
		return &connect, offset, errors.New("insufficient data for CONNECT packet")
	}

	r := NewConnectPacketReader(pkt, offset)

	protocol, err := r.ReadProtocol()
	if err != nil {
		connect.Protocol = protocol // May contain partial data (e.g., Name only)
		return &connect, r.Offset(), err
	}
	connect.Protocol = protocol

	cleanStart, err := r.ReadConnectFlags()
	if err != nil {
		return &connect, r.Offset(), err
	}
	connect.CleanStart = cleanStart

	keepAlive, err := r.ReadKeepAlive()
	if err != nil {
		return &connect, r.Offset(), err
	}
	connect.KeepAlive = keepAlive

	if connect.Protocol.Level == ProtocolLevelMQTT50 {
		if err := r.SkipProperties(); err != nil {
			return &connect, r.Offset(), err
		}
	}

	clientID, err := r.ReadClientID()
	if err != nil {
		return &connect, r.Offset(), err
	}
	connect.ClientID = clientID

	return &connect, r.Offset(), nil
}

// ConnectPacketReader provides domain-specific read methods for CONNECT packets.
// It embeds PacketReader to inherit primitive read operations.
type ConnectPacketReader struct {
	PacketReader
}

// NewConnectPacketReader creates a new ConnectPacketReader starting at the given offset.
func NewConnectPacketReader(pkt []byte, offset int) *ConnectPacketReader {
	return &ConnectPacketReader{PacketReader: NewPacketReader(pkt, offset)}
}

// ReadProtocol reads the protocol name and level from the packet.
func (r *ConnectPacketReader) ReadProtocol() (Protocol, error) {
	nameRaw, err := r.ReadString()
	if err != nil {
		return Protocol{}, err
	}

	name, err := NewProtocolName(nameRaw)
	if err != nil {
		return Protocol{}, err
	}

	levelRaw, err := r.ReadUint8()
	if err != nil {
		return Protocol{Name: name}, err
	}

	return Protocol{Name: name, Level: ProtocolLevel(levelRaw)}, nil
}

// ReadConnectFlags reads the connect flags byte and returns the CleanStart flag.
func (r *ConnectPacketReader) ReadConnectFlags() (cleanStart bool, err error) {
	flags, err := r.ReadUint8()
	if err != nil {
		return false, err
	}
	// Bit 1 is Clean Start flag
	return (flags & 0x02) != 0, nil
}

// ReadKeepAlive reads the keep alive value (in seconds).
func (r *ConnectPacketReader) ReadKeepAlive() (uint16, error) {
	return r.ReadUint16()
}

// SkipProperties reads the property length and skips over the properties bytes.
// This is used for MQTT 5.0 packets.
func (r *ConnectPacketReader) SkipProperties() error {
	propLen, err := r.ReadVariableByteInteger()
	if err != nil {
		return err
	}
	return r.Skip(propLen)
}

// ReadClientID reads the client identifier from the payload.
func (r *ConnectPacketReader) ReadClientID() (string, error) {
	return r.ReadString()
}

type Protocol struct {
	Name  ProtocolName
	Level ProtocolLevel
}

func NewProtocol(name string, level uint8) (*Protocol, error) {
	n, err := NewProtocolName(name)
	if err != nil {
		return nil, err
	}

	l, err := NewProtocolLevel(level)
	if err != nil {
		return nil, err
	}

	return &Protocol{
		Name:  n,
		Level: l,
	}, nil
}

func (p Protocol) IsValid() bool {
	switch p.Level {
	case ProtocolLevelMQTT31:
		return p.Name == ProtocolNameMQIsdp
	case ProtocolLevelMQTT311, ProtocolLevelMQTT50:
		return p.Name == ProtocolNameMQTT
	default:
		return false
	}
}

type ProtocolName string

const (
	ProtocolNameMQTT   ProtocolName = "MQTT"
	ProtocolNameMQIsdp ProtocolName = "MQIsdp"
)

func NewProtocolName(name string) (ProtocolName, error) {
	switch name {
	case string(ProtocolNameMQTT), string(ProtocolNameMQIsdp):
		return ProtocolName(name), nil
	default:
		return "", fmt.Errorf("%q is not a recognized mqtt protocol name", name)
	}
}

func (pn ProtocolName) String() string {
	return string(pn)
}

type ProtocolLevel uint8

const (
	ProtocolLevelMQTT31  ProtocolLevel = 3
	ProtocolLevelMQTT311 ProtocolLevel = 4
	ProtocolLevelMQTT50  ProtocolLevel = 5
)

func NewProtocolLevel(level uint8) (ProtocolLevel, error) {
	switch level {
	case 3:
		return ProtocolLevelMQTT31, nil
	case 4:
		return ProtocolLevelMQTT311, nil
	case 5:
		return ProtocolLevelMQTT50, nil
	}
	return 0, fmt.Errorf("%d is not a recognized mqtt protocol level", level)
}

func (pl ProtocolLevel) String() string {
	switch pl {
	case ProtocolLevelMQTT31:
		return "3.1"
	case ProtocolLevelMQTT311:
		return "3.1.1"
	case ProtocolLevelMQTT50:
		return "5.0"
	default:
		return fmt.Sprintf("%d", pl)
	}
}

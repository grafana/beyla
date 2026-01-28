// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"errors"
	"log/slog"
	"unsafe"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/mqttparser"
)

// MQTTInfo holds parsed information from an MQTT packet.
type MQTTInfo struct {
	// PacketType is the MQTT packet type (PUBLISH, SUBSCRIBE, etc.)
	PacketType mqttparser.PacketType

	// Topic is the topic name (for PUBLISH) or topic filter (for SUBSCRIBE).
	Topic string

	// ClientID is the client identifier from CONNECT packets.
	ClientID string

	// QoS is the Quality of Service level.
	QoS mqttparser.QoSLevel

	// PacketID is the packet identifier for QoS > 0.
	PacketID uint16
}

// packetTypeToMethod converts an MQTT packet type to an OpenTelemetry messaging operation name.
func packetTypeToMethod(packetType mqttparser.PacketType) string {
	switch packetType {
	case mqttparser.PacketTypePUBLISH:
		return request.MessagingPublish
	case mqttparser.PacketTypeSUBSCRIBE:
		return request.MessagingProcess
	default:
		return "unknown"
	}
}

// ProcessPossibleMQTTEvent processes a TCP packet and returns error if the packet is not a valid MQTT packet.
// Otherwise, returns MQTTInfo with the processed data. The ignore bool indicates whether the event
// should be ignored for span creation (e.g., control packets like CONNECT).
func ProcessPossibleMQTTEvent(event *TCPRequestInfo, pkt []byte, rpkt []byte) (*MQTTInfo, bool, error) {
	m, ignore, err := ProcessMQTTEvent(pkt)
	if err != nil {
		// If we are getting the information in the response buffer, the event
		// must be reversed and that's how we captured it.
		m, ignore, err = ProcessMQTTEvent(rpkt)
		if err == nil && !ignore {
			reverseTCPEvent(event)
		}
	}
	return m, ignore, err
}

// ProcessMQTTEvent parses MQTT packets from the provided byte slice.
// Returns MQTTInfo for span-worthy packets, or ignore=true for control packets.
func ProcessMQTTEvent(pkt []byte) (*MQTTInfo, bool, error) {
	if len(pkt) < mqttparser.MinPacketLen {
		return nil, true, errors.New("packet too short for MQTT")
	}

	packets, err := mqttparser.ParseMQTTPackets(pkt)
	if err != nil {
		return nil, true, err
	}

	if len(packets) == 0 {
		return nil, true, errors.New("no MQTT packets found")
	}

	// Process the first packet that we can extract span information from
	offset := 0
	for _, packet := range packets {
		info, ignore, err := processMQTTPacket(pkt, offset, packet)
		if err != nil {
			slog.Debug("MQTT packet processing failed, trying next",
				"packetType", packet.FixedHeader.PacketType,
				"offset", offset,
				"error", err)
			offset += packet.Length()
			continue
		}
		if !ignore {
			return info, false, nil
		}
		offset += packet.Length()
	}

	return nil, true, errors.New("no span-worthy MQTT packets found")
}

// processMQTTPacket processes a single MQTT packet based on its type.
func processMQTTPacket(pkt []byte, startOffset int, packet mqttparser.MQTTControlPacket) (*MQTTInfo, bool, error) {
	// Variable header starts after fixed header
	varHeaderOffset := startOffset + packet.FixedHeader.Length

	switch packet.FixedHeader.PacketType {
	case mqttparser.PacketTypePUBLISH:
		return processPublishPacket(pkt, varHeaderOffset, packet.FixedHeader.Flags)
	case mqttparser.PacketTypeSUBSCRIBE:
		return processSubscribePacket(pkt, varHeaderOffset, packet.FixedHeader.RemainingLength)
	case mqttparser.PacketTypeCONNECT:
		return processConnectPacket(pkt, varHeaderOffset)
	case mqttparser.PacketTypeCONNACK,
		mqttparser.PacketTypePUBACK,
		mqttparser.PacketTypePUBREC,
		mqttparser.PacketTypePUBREL,
		mqttparser.PacketTypePUBCOMP,
		mqttparser.PacketTypeSUBACK,
		mqttparser.PacketTypeUNSUBSCRIBE,
		mqttparser.PacketTypeUNSUBACK,
		mqttparser.PacketTypePINGREQ,
		mqttparser.PacketTypePINGRESP,
		mqttparser.PacketTypeDISCONNECT,
		mqttparser.PacketTypeAUTH:
		// Control packets - ignore for span creation
		return nil, true, nil
	default:
		return nil, true, errors.New("unsupported MQTT packet type")
	}
}

func processPublishPacket(pkt []byte, offset int, flags uint8) (*MQTTInfo, bool, error) {
	publish, _, err := mqttparser.ParsePublishPacket(pkt, offset, flags)
	if err != nil {
		return nil, true, err
	}

	return &MQTTInfo{
		PacketType: mqttparser.PacketTypePUBLISH,
		Topic:      publish.TopicName,
		QoS:        publish.QoS,
		PacketID:   publish.PacketID,
	}, false, nil
}

func processSubscribePacket(pkt []byte, offset int, remainingLength int) (*MQTTInfo, bool, error) {
	subscribe, _, err := mqttparser.ParseSubscribePacket(pkt, offset, remainingLength)
	if err != nil {
		return nil, true, err
	}

	if len(subscribe.Subscriptions) == 0 {
		return nil, true, errors.New("no subscriptions found")
	}

	// Use the first subscription for the span
	firstSub := subscribe.Subscriptions[0]
	return &MQTTInfo{
		PacketType: mqttparser.PacketTypeSUBSCRIBE,
		Topic:      firstSub.TopicFilter,
		QoS:        firstSub.QoS,
		PacketID:   subscribe.PacketID,
	}, false, nil
}

func processConnectPacket(pkt []byte, offset int) (*MQTTInfo, bool, error) {
	connect, _, err := mqttparser.ParseConnectPacket(pkt, offset)
	if err != nil {
		return nil, true, err
	}

	// CONNECT packets are typically ignored for span creation,
	// but we return the ClientID for potential context caching
	return &MQTTInfo{
		PacketType: mqttparser.PacketTypeCONNECT,
		ClientID:   connect.ClientID,
	}, true, nil // ignore=true for CONNECT as it's a control operation
}

// isMQTT performs a quick heuristic check to determine if the packet looks like MQTT.
// This is used for userspace protocol detection when the kernel hasn't classified the protocol.
func isMQTT(pkt []byte) bool {
	_, err := mqttparser.NewMQTTControlPacket(pkt)
	return err == nil
}

// TCPToMQTTToSpan converts a TCPRequestInfo and MQTTInfo into a request.Span.
func TCPToMQTTToSpan(trace *TCPRequestInfo, data *MQTTInfo) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0

	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.ConnInfo)).reqHostInfo()
		hostPort = int(trace.ConnInfo.D_port)
	}

	reqType := request.EventTypeMQTTClient
	if trace.Direction == 0 {
		reqType = request.EventTypeMQTTServer
	}

	return request.Span{
		Type:          reqType,
		Method:        packetTypeToMethod(data.PacketType),
		Path:          data.Topic,
		Statement:     data.ClientID,
		Peer:          peer,
		PeerPort:      int(trace.ConnInfo.S_port),
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: 0,
		RequestStart:  int64(trace.StartMonotimeNs),
		Start:         int64(trace.StartMonotimeNs),
		End:           int64(trace.EndMonotimeNs),
		Status:        0,
		TraceID:       trace.Tp.TraceId,
		SpanID:        trace.Tp.SpanId,
		ParentSpanID:  trace.Tp.ParentId,
		TraceFlags:    trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   trace.Pid.HostPid,
			UserPID:   trace.Pid.UserPid,
			Namespace: trace.Pid.Ns,
		},
	}
}

package ebpfcommon

import (
	"encoding/binary"
	"errors"

	trace2 "go.opentelemetry.io/otel/trace"

	"github.com/grafana/beyla/pkg/internal/request"
)

type Operation int8

const (
	Produce Operation = 0
	Fetch   Operation = 1
)

type Header struct {
	MessageSize   int32
	APIKey        int16
	APIVersion    int16
	CorrelationID int32
	ClientIDSize  int16
}

type KafkaInfo struct {
	Operation   Operation
	Topic       string
	ClientID    string
	TopicOffset int
}

func (k Operation) String() string {
	switch k {
	case Produce:
		return request.MessagingPublish
	case Fetch:
		return request.MessagingProcess
	default:
		return "unknown"
	}
}

const KafaMinLength = 14

// ProcessKafkaRequest processes a TCP packet and returns error if the packet is not a valid Kafka request.
// Otherwise, return kafka.Info with the processed data.
func ProcessPossibleKafkaEvent(pkt []byte, rpkt []byte) (*KafkaInfo, error) {
	k, err := ProcessKafkaRequest(pkt)
	if err != nil {
		k, err = ProcessKafkaRequest(rpkt)
	}

	return k, err
}

func ProcessKafkaRequest(pkt []byte) (*KafkaInfo, error) {
	k := &KafkaInfo{}
	if len(pkt) < KafaMinLength {
		return k, errors.New("packet too short")
	}

	header := &Header{
		MessageSize:   int32(binary.BigEndian.Uint32(pkt[0:4])),
		APIKey:        int16(binary.BigEndian.Uint16(pkt[4:6])),
		APIVersion:    int16(binary.BigEndian.Uint16(pkt[6:8])),
		CorrelationID: int32(binary.BigEndian.Uint32(pkt[8:12])),
		ClientIDSize:  int16(binary.BigEndian.Uint16(pkt[12:14])),
	}

	if !isValidKafkaHeader(header) {
		return k, errors.New("invalid Kafka request header")
	}

	offset := KafaMinLength
	if header.ClientIDSize > 0 {
		clientID := pkt[offset : offset+int(header.ClientIDSize)]
		if !isValidClientID(clientID, int(header.ClientIDSize)) {
			return k, errors.New("invalid client ID")
		}
		offset += int(header.ClientIDSize)
		k.ClientID = string(clientID)
	} else if header.ClientIDSize < -1 {
		return k, errors.New("invalid client ID size")
	}

	switch Operation(header.APIKey) {
	case Produce:
		ok, err := getTopicOffsetFromProduceOperation(header, pkt, &offset)
		if !ok || err != nil {
			return k, err
		}
		k.Operation = Produce
		k.TopicOffset = offset
	case Fetch:
		offset += getTopicOffsetFromFetchOperation(header)
		k.Operation = Fetch
		k.TopicOffset = offset
	default:
		return k, errors.New("invalid Kafka operation")
	}
	topic, err := getTopicName(pkt, offset)
	if err != nil {
		return k, err
	}
	k.Topic = topic
	return k, nil
}

func isValidKafkaHeader(header *Header) bool {
	if header.MessageSize < int32(KafaMinLength) || header.APIVersion < 0 {
		return false
	}
	switch Operation(header.APIKey) {
	case Fetch:
		if header.APIVersion > 11 {
			return false
		}
	case Produce:
		if header.APIVersion == 0 || header.APIVersion > 8 {
			return false
		}
	default:
		return false
	}
	if header.CorrelationID < 0 {
		return false
	}
	return header.ClientIDSize >= -1
}

// nolint:cyclop
func isValidKafkaString(buffer []byte, maxBufferSize, realSize int, printableOk bool) bool {
	for j := 0; j < maxBufferSize; j++ {
		if j >= realSize {
			break
		}
		ch := buffer[j]
		if ('a' <= ch && ch <= 'z') || ('A' <= ch && ch <= 'Z') || ('0' <= ch && ch <= '9') || ch == '.' || ch == '_' || ch == '-' {
			continue
		}
		if printableOk && (ch >= ' ' && ch <= '~') {
			continue
		}
		return false
	}
	return true
}

func isValidClientID(buffer []byte, realClientIDSize int) bool {
	return isValidKafkaString(buffer, len(buffer), realClientIDSize, true)
}

func getTopicName(pkt []byte, offset int) (string, error) {
	offset += 4
	if offset > len(pkt) {
		return "", errors.New("invalid buffer length")
	}
	topicNameSize := int16(binary.BigEndian.Uint16(pkt[offset:]))
	if topicNameSize <= 0 || topicNameSize > 255 {
		return "", errors.New("invalid topic name size")
	}
	offset += 2

	if offset > len(pkt) {
		return "", nil
	}
	maxLen := offset + int(topicNameSize)
	if len(pkt) < maxLen {
		maxLen = len(pkt)
	}
	topicName := pkt[offset:maxLen]
	if isValidKafkaString(topicName, len(topicName), int(topicNameSize), false) {
		return string(topicName), nil
	}
	return "", errors.New("invalid topic name")
}

func getTopicOffsetFromProduceOperation(header *Header, pkt []byte, offset *int) (bool, error) {
	if header.APIVersion >= 3 {
		if len(pkt) < *offset+2 {
			return false, errors.New("packet too short")
		}
		transactionalIDSize := int16(binary.BigEndian.Uint16(pkt[*offset:]))
		*offset += 2
		if transactionalIDSize > 0 {
			*offset += int(transactionalIDSize)
		}
	}

	if len(pkt) < *offset+2 {
		return false, errors.New("packet too short")
	}
	acks := int16(binary.BigEndian.Uint16(pkt[*offset:]))
	if acks < -1 || acks > 1 {
		return false, nil
	}
	*offset += 2

	if len(pkt) < *offset+4 {
		return false, errors.New("packet too short")
	}
	timeoutMS := int32(binary.BigEndian.Uint32(pkt[*offset:]))
	if timeoutMS < 0 {
		return false, nil
	}
	*offset += 4

	return true, nil
}

func getTopicOffsetFromFetchOperation(header *Header) int {
	offset := 3 * 4 // 3 * sizeof(int32)

	if header.APIVersion >= 3 {
		offset += 4 // max_bytes
		if header.APIVersion >= 4 {
			offset++ // isolation_level
			if header.APIVersion >= 7 {
				offset += 2 * 4 // session_id + session_epoch
			}
		}
	}

	return offset
}

func TCPToKafkaToSpan(trace *TCPRequestInfo, data *KafkaInfo) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0

	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = trace.reqHostInfo()
		hostPort = int(trace.ConnInfo.D_port)
	}
	return request.Span{
		Type:           request.EventTypeKafkaClient,
		Method:         data.Operation.String(),
		OtherNamespace: data.ClientID,
		Path:           data.Topic,
		Peer:           peer,
		Host:           hostname,
		HostPort:       hostPort,
		ContentLength:  0,
		RequestStart:   int64(trace.StartMonotimeNs),
		Start:          int64(trace.StartMonotimeNs),
		End:            int64(trace.EndMonotimeNs),
		Status:         0,
		TraceID:        trace2.TraceID(trace.Tp.TraceId),
		SpanID:         trace2.SpanID(trace.Tp.SpanId),
		ParentSpanID:   trace2.SpanID(trace.Tp.ParentId),
		Flags:          trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   trace.Pid.HostPid,
			UserPID:   trace.Pid.UserPid,
			Namespace: trace.Pid.Ns,
		},
	}
}

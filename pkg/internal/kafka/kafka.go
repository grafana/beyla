package kafka

import (
	"encoding/binary"
	"errors"
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

type Info struct {
	Operation   Operation
	Topic       string
	ClientID    string
	TopicOffset int
}

func (k Operation) String() string {
	switch k {
	case Produce:
		return "process"
	case Fetch:
		return "receive"
	default:
		return "unknown"
	}
}

const KafaMinLength = 14

// ProcessKafkaData processes a TCP packet and returns error if the packet is not a valid Kafka request.
// Otherwise, return KafkaData with the processed data.
func ProcessKafkaData(pkt []byte) (*Info, error) {
	k := &Info{}
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
func isValidString(buffer []byte, maxBufferSize, realSize int, printableOk bool) bool {
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
	return isValidString(buffer, len(buffer), realClientIDSize, true)
}

func getTopicName(pkt []byte, offset int) (string, error) {
	offset += 4
	topicNameSize := int16(binary.BigEndian.Uint16(pkt[offset:]))
	if topicNameSize <= 0 || topicNameSize > 255 {
		return "", errors.New("invalid topic name size")
	}
	offset += 2

	if len(pkt) < offset+int(topicNameSize) {
		return "", errors.New("packet too short")
	}
	topicName := pkt[offset : offset+int(topicNameSize)]
	if isValidString(topicName, len(topicName), int(topicNameSize), false) {
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

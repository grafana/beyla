package kafka

import (
	"encoding/binary"
	"errors"
)

type KafkaOperation int8

const (
	KAFKA_PRODUCE KafkaOperation = 0
	KAFKA_FETCH   KafkaOperation = 1
)

type KafkaHeader struct {
	MessageSize   int32
	ApiKey        int16
	ApiVersion    int16
	CorrelationID int32
	ClientIDSize  int16
}

type KafkaData struct {
	KafkaOperation KafkaOperation
	Topic          string
	ClientID       string
	TopicOffset    int
}

func (k KafkaOperation) String() string {
	switch k {
	case KAFKA_PRODUCE:
		return "process"
	case KAFKA_FETCH:
		return "receive"
	default:
		return "unknown"
	}
}

const KAFKA_MIN_LENGTH = 14

// ProcessKafkaData processes a TCP packet and returns error if the packet is not a valid Kafka request.
// Otherwise, return KafkaData with the processed data.
func ProcessKafkaData(pkt []byte) (*KafkaData, error) {
	k := &KafkaData{}
	if len(pkt) < KAFKA_MIN_LENGTH {
		return k, errors.New("packet too short")
	}

	header := &KafkaHeader{
		MessageSize:   int32(binary.BigEndian.Uint32(pkt[0:4])),
		ApiKey:        int16(binary.BigEndian.Uint16(pkt[4:6])),
		ApiVersion:    int16(binary.BigEndian.Uint16(pkt[6:8])),
		CorrelationID: int32(binary.BigEndian.Uint32(pkt[8:12])),
		ClientIDSize:  int16(binary.BigEndian.Uint16(pkt[12:14])),
	}

	if !isValidKafkaHeader(header) {
		return k, errors.New("invalid Kafka request header")
	}

	offset := KAFKA_MIN_LENGTH
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

	switch KafkaOperation(header.ApiKey) {
	case KAFKA_PRODUCE:
		ok, err := getTopicOffsetFromProduceOperation(header, pkt, &offset)
		if !ok || err != nil {
			return k, err
		}
		k.KafkaOperation = KAFKA_PRODUCE
		k.TopicOffset = offset
	case KAFKA_FETCH:
		offset += getTopicOffsetFromFetchOperation(header)
		k.KafkaOperation = KAFKA_FETCH
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

func isValidKafkaHeader(header *KafkaHeader) bool {
	if header.MessageSize < int32(KAFKA_MIN_LENGTH) || header.ApiVersion < 0 {
		return false
	}
	switch KafkaOperation(header.ApiKey) {
	case KAFKA_FETCH:
		if header.ApiVersion > 11 {
			return false
		}
	case KAFKA_PRODUCE:
		if header.ApiVersion == 0 || header.ApiVersion > 8 {
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

func getTopicOffsetFromProduceOperation(header *KafkaHeader, pkt []byte, offset *int) (bool, error) {
	if header.ApiVersion >= 3 {
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

func getTopicOffsetFromFetchOperation(header *KafkaHeader) int {
	offset := 3 * 4 // 3 * sizeof(int32)

	if header.ApiVersion >= 3 {
		offset += 4 // max_bytes
		if header.ApiVersion >= 4 {
			offset += 1 // isolation_level
			if header.ApiVersion >= 7 {
				offset += 2 * 4 // session_id + session_epoch
			}
		}
	}

	return offset
}

package ebpfcommon

import (
	"encoding/binary"
	"errors"
	"regexp"
	"unsafe"

	trace2 "go.opentelemetry.io/otel/trace"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/app/request"
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

const (
	KafkaMinLength  = 14
	KafkaMaxPayload = 20 * 1024 * 1024 // 20 MB max, 1MB is default for most Kafka installations
)

var topicRegex = regexp.MustCompile("\x02\t(.*)\x02")

// ProcessPossibleKafkaEvent processes a TCP packet and returns error if the packet is not a valid Kafka request.
// Otherwise, return kafka.Info with the processed data.
func ProcessPossibleKafkaEvent(event *TCPRequestInfo, pkt []byte, rpkt []byte) (*KafkaInfo, error) {
	k, err := ProcessKafkaRequest(pkt)
	if err != nil {
		// If we are getting the information in the response buffer, the event
		// must be reversed and that's how we captured it.
		k, err = ProcessKafkaRequest(rpkt)
		if err == nil {
			reverseTCPEvent(event)
		}
	}
	return k, err
}

// ProcessKafkaRequest according to https://kafka.apache.org/protocol.html
func ProcessKafkaRequest(pkt []byte) (*KafkaInfo, error) {
	k := &KafkaInfo{}
	if len(pkt) < KafkaMinLength {
		return k, errors.New("packet too short")
	}

	header, err := parseKafkaHeader(pkt)
	if err != nil {
		return k, err
	}

	if len(pkt) < KafkaMinLength+int(header.ClientIDSize) {
		return k, errors.New("packet too short")
	}

	offset, err := processClientID(header, pkt, k)
	if err != nil {
		return k, err
	}

	err = processKafkaOperation(header, pkt, k, &offset)
	if err != nil {
		return k, err
	}

	topic, err := getTopicName(pkt, offset, k.Operation, header.APIVersion)
	if err != nil {
		return k, err
	}
	k.Topic = topic
	return k, nil
}

func parseKafkaHeader(pkt []byte) (*Header, error) {
	header := &Header{
		MessageSize:   int32(binary.BigEndian.Uint32(pkt[0:4])),
		APIKey:        int16(binary.BigEndian.Uint16(pkt[4:6])),
		APIVersion:    int16(binary.BigEndian.Uint16(pkt[6:8])),
		CorrelationID: int32(binary.BigEndian.Uint32(pkt[8:12])),
		ClientIDSize:  int16(binary.BigEndian.Uint16(pkt[12:14])),
	}

	if !isValidKafkaHeader(header) {
		return nil, errors.New("invalid Kafka request header")
	}
	return header, nil
}

func isValidKafkaHeader(header *Header) bool {
	if header.MessageSize < int32(KafkaMinLength) || header.APIVersion < 0 {
		return false
	}

	if header.MessageSize > KafkaMaxPayload {
		return false
	}

	switch Operation(header.APIKey) {
	case Fetch:
		if header.APIVersion > 16 { // latest: Fetch Request (Version: 16)
			return false
		}
	case Produce:
		if header.APIVersion == 0 || header.APIVersion > 10 { // latest: Produce Request (Version: 10)
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

func processClientID(header *Header, pkt []byte, k *KafkaInfo) (int, error) {
	offset := KafkaMinLength
	if header.ClientIDSize > 0 {
		clientID := pkt[offset : offset+int(header.ClientIDSize)]
		if !isValidClientID(clientID, int(header.ClientIDSize)) {
			return 0, errors.New("invalid client ID")
		}
		offset += int(header.ClientIDSize)
		k.ClientID = string(clientID)
	} else if header.ClientIDSize < -1 {
		return 0, errors.New("invalid client ID size")
	}
	return offset, nil
}

func processKafkaOperation(header *Header, pkt []byte, k *KafkaInfo, offset *int) error {
	switch Operation(header.APIKey) {
	case Produce:
		ok, err := getTopicOffsetFromProduceOperation(header, pkt, offset)
		if !ok || err != nil {
			return err
		}
		k.Operation = Produce
		k.TopicOffset = *offset
	case Fetch:
		to, err := getTopicOffsetFromFetchOperation(pkt, *offset, header)
		if err != nil {
			return err
		}
		*offset += to
		k.Operation = Fetch
		k.TopicOffset = *offset
	default:
		return errors.New("invalid Kafka operation")
	}
	return nil
}

//nolint:cyclop
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

func getTopicName(pkt []byte, offset int, op Operation, apiVersion int16) (string, error) {
	if apiVersion >= 13 { // topic name is only a UUID, no need to parse it
		return "*", nil
	}

	offset += 4
	if offset >= len(pkt) {
		return "", errors.New("invalid buffer length")
	}
	topicNameSize, err := getTopicNameSize(pkt, offset, op, apiVersion)
	if err != nil {
		return "", err
	}
	offset += 2

	if offset >= len(pkt) {
		return "", nil
	}
	maxLen := offset + topicNameSize
	if len(pkt) < maxLen {
		maxLen = len(pkt)
	}
	topicName := pkt[offset:maxLen]
	if op == Fetch && apiVersion > 11 {
		// topic name has the following format: uuid\x00\x02\tTOPIC\x02\x00
		topicName = []byte(extractTopic(string(topicName)))
	}
	if isValidKafkaString(topicName, len(topicName), topicNameSize, false) {
		if op == Fetch && apiVersion <= 11 && len(topicName) == 0 {
			return "", errors.New("topic name must not be empty for api version <= 11")
		}
		return string(topicName), nil
	}
	return "", errors.New("invalid topic name")
}

func extractTopic(input string) string {
	matches := topicRegex.FindStringSubmatch(input)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func getTopicNameSize(pkt []byte, offset int, op Operation, apiVersion int16) (int, error) {
	topicNameSize := 0
	if (op == Produce && apiVersion > 7) || (op == Fetch && apiVersion > 11) { // topic is a compact string
		var err error
		topicNameSize, err = readUnsignedVarint(pkt[offset+1:])
		topicNameSize--
		if err != nil {
			return 0, err
		}
	} else if offset < (len(pkt) - 1) { // we need at least 2 bytes to read uint16
		topicNameSize = int(binary.BigEndian.Uint16(pkt[offset:]))
	}
	if topicNameSize <= 0 {
		return 0, errors.New("invalid topic name size")
	}
	return topicNameSize, nil
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
	if header.APIVersion <= 7 {
		*offset += 4
	}

	return true, nil
}

func getTopicOffsetFromFetchOperation(pkt []byte, origOffset int, header *Header) (int, error) {
	offset := 3 * 4 // 3 * sizeof(int32)

	if header.APIVersion >= 15 {
		offset -= 4 // no replica id
	}

	if header.APIVersion >= 3 {
		offset += 4 // max_bytes
		if header.APIVersion >= 4 {
			if origOffset+offset >= len(pkt) {
				return 0, errors.New("packet too small")
			}
			isolation := pkt[origOffset+offset]
			if isolation > 1 {
				return 0, errors.New("wrong isolation level")
			}
			offset++ // isolation_level
			if header.APIVersion >= 7 {
				offset += 2 * 4 // session_id + session_epoch
			}
		}
	}

	return offset, nil
}

func readUnsignedVarint(data []byte) (int, error) {
	value := 0
	i := 0
	for idx := 0; idx < len(data); idx++ {
		b := data[idx]
		if (b & 0x80) == 0 {
			value |= int(b) << i
			return value, nil
		}
		value |= int(b&0x7F) << i
		i += 7
		if i > 28 {
			return 0, errors.New("illegal varint")
		}
	}
	return 0, errors.New("data ended before varint was complete")
}

func TCPToKafkaToSpan(trace *TCPRequestInfo, data *KafkaInfo) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0

	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.ConnInfo)).reqHostInfo()
		hostPort = int(trace.ConnInfo.D_port)
	}

	reqType := request.EventTypeKafkaClient
	if trace.Direction == 0 {
		reqType = request.EventTypeKafkaServer
	}

	return request.Span{
		Type:          reqType,
		Method:        data.Operation.String(),
		Statement:     data.ClientID,
		Path:          data.Topic,
		Peer:          peer,
		PeerPort:      int(trace.ConnInfo.S_port),
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: 0,
		RequestStart:  int64(trace.StartMonotimeNs),
		Start:         int64(trace.StartMonotimeNs),
		End:           int64(trace.EndMonotimeNs),
		Status:        0,
		TraceID:       trace2.TraceID(trace.Tp.TraceId),
		SpanID:        trace2.SpanID(trace.Tp.SpanId),
		ParentSpanID:  trace2.SpanID(trace.Tp.ParentId),
		TraceFlags:    trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   trace.Pid.HostPid,
			UserPID:   trace.Pid.UserPid,
			Namespace: trace.Pid.Ns,
		},
	}
}

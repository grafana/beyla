// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"errors"
	"unsafe"

	"github.com/hashicorp/golang-lru/v2/simplelru"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/kafkaparser"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

type Operation int8

const (
	Produce Operation = 0
	Fetch   Operation = 1
)

var (
	errKafkaUnsupportedAPIKey           = errors.New("unsupported Kafka API key")
	errKafkaNoResponseBufferForMetadata = errors.New("no response buffer for metadata request")
)

type PartitionInfo struct {
	Partition int
	Offset    int64
}

type KafkaInfo struct {
	Operation     Operation
	Topic         string
	ClientID      string
	PartitionInfo *PartitionInfo
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

// ProcessPossibleKafkaEvent processes a TCP packet and returns error if the packet is not a valid Kafka request.
// Otherwise, it returns one KafkaInfo per topic in the request (a single Produce/Fetch request can
// reference multiple topics).
func ProcessPossibleKafkaEvent(event *TCPRequestInfo, pkt *largebuf.LargeBuffer, rpkt *largebuf.LargeBuffer, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) ([]*KafkaInfo, bool, error) {
	k, ok, err := ProcessKafkaEvent(pkt, rpkt, kafkaTopicUUIDToName)
	if err != nil {
		// If we are getting the information in the response buffer, the event
		// must be reversed and that's how we captured it.
		k, ok, err = ProcessKafkaEvent(rpkt, pkt, kafkaTopicUUIDToName)
		if err == nil {
			reverseTCPEvent(event)
		}
	}
	return k, ok, err
}

func ProcessKafkaEvent(pkt *largebuf.LargeBuffer, rpkt *largebuf.LargeBuffer, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) ([]*KafkaInfo, bool, error) {
	hdr, err := kafkaparser.NewKafkaRequestHeader(pkt)
	if err != nil {
		return nil, true, err
	}
	switch hdr.APIKey() {
	case kafkaparser.APIKeyProduce:
		return processProduceRequest(hdr, kafkaTopicUUIDToName)
	case kafkaparser.APIKeyFetch:
		return processFetchRequest(hdr, kafkaTopicUUIDToName)
	case kafkaparser.APIKeyMetadata:
		return processMetadataResponse(rpkt, hdr, kafkaTopicUUIDToName)
	default:
		return nil, true, errKafkaUnsupportedAPIKey
	}
}

func processProduceRequest(hdr kafkaparser.KafkaRequestHeader, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) ([]*KafkaInfo, bool, error) {
	r, err := hdr.NewBodyReader()
	if err != nil {
		return nil, true, err
	}

	produceReq, err := kafkaparser.ParseProduceRequest(&r, hdr)
	if err != nil {
		return nil, true, err
	}
	clientID := hdr.ClientID()
	infos := make([]*KafkaInfo, 0, len(produceReq.Topics))
	for _, topic := range produceReq.Topics {
		topicName := topic.Name
		if topic.UUID != nil {
			topicName = "*"
			if kafkaTopicUUIDToName != nil {
				if name, found := kafkaTopicUUIDToName.Get(*topic.UUID); found {
					topicName = name
				}
			}
		}
		var partitionInfo *PartitionInfo
		if topic.Partition != nil {
			partitionInfo = &PartitionInfo{
				Partition: *topic.Partition,
			}
		}
		infos = append(infos, &KafkaInfo{
			ClientID:      clientID,
			Operation:     Produce,
			Topic:         topicName,
			PartitionInfo: partitionInfo,
		})
	}
	return infos, false, nil
}

func processFetchRequest(hdr kafkaparser.KafkaRequestHeader, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) ([]*KafkaInfo, bool, error) {
	r, err := hdr.NewBodyReader()
	if err != nil {
		return nil, true, err
	}

	fetchReq, err := kafkaparser.ParseFetchRequest(&r, hdr)
	if err != nil {
		return nil, true, err
	}
	clientID := hdr.ClientID()
	infos := make([]*KafkaInfo, 0, len(fetchReq.Topics))
	for _, topic := range fetchReq.Topics {
		topicName := topic.Name
		// Fetch v13+ identifies topics by UUID; resolve it via the cache filled
		// from Metadata responses.
		if topic.UUID != nil {
			topicName = "*"
			if kafkaTopicUUIDToName != nil {
				if name, found := kafkaTopicUUIDToName.Get(*topic.UUID); found {
					topicName = name
				}
			}
		}
		var partitionInfo *PartitionInfo
		if topic.Partition != nil {
			partitionInfo = &PartitionInfo{
				Partition: topic.Partition.Partition,
				Offset:    topic.Partition.FetchOffset,
			}
		}
		infos = append(infos, &KafkaInfo{
			ClientID:      clientID,
			Operation:     Fetch,
			Topic:         topicName,
			PartitionInfo: partitionInfo,
		})
	}
	return infos, false, nil
}

func processMetadataResponse(rpkt *largebuf.LargeBuffer, hdr kafkaparser.KafkaRequestHeader, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) ([]*KafkaInfo, bool, error) {
	if rpkt == nil {
		return nil, true, errKafkaNoResponseBufferForMetadata
	}
	// only interested in response
	r := rpkt.NewReader()
	_, err := kafkaparser.ParseKafkaResponseHeader(&r, hdr)
	if err != nil {
		return nil, true, err
	}
	metadataResponse, err := kafkaparser.ParseMetadataResponse(&r, hdr)
	if err != nil {
		return nil, true, err
	}
	for _, topic := range metadataResponse.Topics {
		kafkaTopicUUIDToName.Add(topic.UUID, topic.Name)
	}
	return nil, true, nil
}

func ProcessKafkaRequest(pkt *largebuf.LargeBuffer, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) ([]*KafkaInfo, bool, error) {
	hdr, err := kafkaparser.NewKafkaRequestHeader(pkt)
	if err != nil {
		return nil, true, err
	}
	switch hdr.APIKey() {
	case kafkaparser.APIKeyProduce:
		return processProduceRequest(hdr, kafkaTopicUUIDToName)
	case kafkaparser.APIKeyFetch:
		return processFetchRequest(hdr, kafkaTopicUUIDToName)
	default:
		return nil, true, errKafkaUnsupportedAPIKey
	}
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

	var messagingInfo *request.MessagingInfo

	if data.PartitionInfo != nil {
		messagingInfo = &request.MessagingInfo{
			Partition: data.PartitionInfo.Partition,
			Offset:    data.PartitionInfo.Offset,
		}
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
		TraceID:       trace.Tp.TraceId,
		SpanID:        trace.Tp.SpanId,
		ParentSpanID:  trace.Tp.ParentId,
		TraceFlags:    trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   app.PID(trace.Pid.HostPid),
			UserPID:   app.PID(trace.Pid.UserPid),
			Namespace: trace.Pid.Ns,
		},
		MessagingInfo: messagingInfo,
	}
}

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

// unknownTopicName is reported when a topic is identified by UUID (KIP-516) and its
// name has not been learned from a Metadata response yet.
const unknownTopicName = "*"

type PartitionInfo struct {
	Partition int
	Offset    int64
}

type KafkaInfo struct {
	Operation     Operation
	Topic         string
	ClientID      string
	PartitionInfo *PartitionInfo
	// ConsumerGroup is set on Fetch requests when the group of the fetching process
	// is known (see KafkaConsumerGroups); producers never have one.
	ConsumerGroup string
}

func (k Operation) String() string {
	switch k {
	case Produce:
		return request.MessagingSend
	case Fetch:
		return request.MessagingProcess
	default:
		return "unknown"
	}
}

// ProcessPossibleKafkaEvent processes a TCP packet and returns error if the packet is not a valid Kafka request.
// Otherwise, it returns one KafkaInfo per topic in the request (a single Produce/Fetch request can
// reference multiple topics).
func ProcessPossibleKafkaEvent(event *TCPRequestInfo, pkt *largebuf.LargeBuffer, rpkt *largebuf.LargeBuffer, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string], groups *KafkaConsumerGroups) ([]*KafkaInfo, bool, error) {
	proc := KafkaProcess{Ns: event.Pid.Ns, Pid: event.Pid.UserPid}
	k, ok, err := ProcessKafkaEvent(pkt, rpkt, kafkaTopicUUIDToName, clientGroups(groups, event.Direction), proc, event.ConnInfo)
	if err != nil {
		// If we are getting the information in the response buffer, the event
		// must be reversed and that's how we captured it.
		k, ok, err = ProcessKafkaEvent(rpkt, pkt, kafkaTopicUUIDToName, clientGroups(groups, reverseDirection(event.Direction)), proc, event.ConnInfo)
		if err == nil {
			reverseTCPEvent(event)
		}
	}
	return k, ok, err
}

// clientGroups returns the consumer group cache only for client-side events. A broker
// receives the group requests of every client, so learning or reporting groups under the
// broker's pid would attribute an arbitrary client's group to server spans.
func clientGroups(groups *KafkaConsumerGroups, direction uint8) *KafkaConsumerGroups {
	if direction == directionRecv {
		return nil
	}
	return groups
}

func ProcessKafkaEvent(pkt *largebuf.LargeBuffer, rpkt *largebuf.LargeBuffer, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string], groups *KafkaConsumerGroups, proc KafkaProcess, conn BpfConnectionInfoT) ([]*KafkaInfo, bool, error) {
	hdr, err := kafkaparser.NewKafkaRequestHeader(pkt)
	if err != nil {
		return nil, true, err
	}
	switch hdr.APIKey() {
	case kafkaparser.APIKeyProduce:
		return processProduceRequest(hdr, kafkaTopicUUIDToName)
	case kafkaparser.APIKeyFetch:
		return processFetchRequest(hdr, kafkaTopicUUIDToName, groups, proc)
	case kafkaparser.APIKeyMetadata:
		return processMetadataResponse(rpkt, hdr, kafkaTopicUUIDToName)
	case kafkaparser.APIKeyOffsetCommit, kafkaparser.APIKeyOffsetFetch, kafkaparser.APIKeyJoinGroup,
		kafkaparser.APIKeyHeartbeat, kafkaparser.APIKeyLeaveGroup, kafkaparser.APIKeySyncGroup,
		kafkaparser.APIKeyConsumerGroupHeartbeat:
		return processGroupRequest(hdr, kafkaTopicUUIDToName, groups, proc, conn)
	default:
		return nil, true, errKafkaUnsupportedAPIKey
	}
}

// processGroupRequest updates the consumer group membership of the requesting process.
// Like Metadata, these requests never produce a span.
func processGroupRequest(hdr kafkaparser.KafkaRequestHeader, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string], groups *KafkaConsumerGroups, proc KafkaProcess, conn BpfConnectionInfoT) ([]*KafkaInfo, bool, error) {
	r, err := hdr.NewBodyReader()
	if err != nil {
		return nil, true, err
	}
	groupReq, err := kafkaparser.ParseGroupRequest(&r, hdr)
	if err != nil {
		return nil, true, err
	}
	switch hdr.APIKey() {
	case kafkaparser.APIKeyOffsetCommit, kafkaparser.APIKeyOffsetFetch:
		groups.Enrich(proc, groupReq, kafkaTopicUUIDToName)
	case kafkaparser.APIKeyLeaveGroup:
		groups.Leave(proc, conn, groupReq.GroupID, groupReq.Members)
	case kafkaparser.APIKeyConsumerGroupHeartbeat:
		if groupReq.MemberEpoch < 0 {
			groups.Leave(proc, conn, groupReq.GroupID, []string{groupReq.MemberID})
		} else {
			groups.Join(proc, conn, groupReq, kafkaTopicUUIDToName)
		}
	case kafkaparser.APIKeyJoinGroup, kafkaparser.APIKeySyncGroup, kafkaparser.APIKeyHeartbeat:
		groups.Join(proc, conn, groupReq, kafkaTopicUUIDToName)
	default:
		return nil, true, errKafkaUnsupportedAPIKey
	}
	return nil, true, nil
}

// resolveTopicName returns the topic name, resolving a KIP-516 UUID through the cache
// filled from Metadata responses; "" when the UUID is not known yet.
func resolveTopicName(name string, uuid *kafkaparser.UUID, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) string {
	if uuid == nil {
		return name
	}
	if kafkaTopicUUIDToName == nil {
		return ""
	}
	resolved, _ := kafkaTopicUUIDToName.Get(*uuid)
	return resolved
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
		topicName := resolveTopicName(topic.Name, topic.UUID, kafkaTopicUUIDToName)
		if topicName == "" {
			topicName = unknownTopicName
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

func processFetchRequest(hdr kafkaparser.KafkaRequestHeader, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string], groups *KafkaConsumerGroups, proc KafkaProcess) ([]*KafkaInfo, bool, error) {
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
		resolvedTopic := resolveTopicName(topic.Name, topic.UUID, kafkaTopicUUIDToName)
		topicName := resolvedTopic
		if topicName == "" {
			topicName = unknownTopicName
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
			ConsumerGroup: groups.Lookup(proc, resolvedTopic), // "" -> single consumer group of the process, if any
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

// kafkaMessagingInfo returns nil when neither the partition nor the consumer group is
// known, so exporters emit no partition/offset/group attributes at all.
func kafkaMessagingInfo(data *KafkaInfo) *request.MessagingInfo {
	if data.PartitionInfo == nil && data.ConsumerGroup == "" {
		return nil
	}
	info := &request.MessagingInfo{ConsumerGroup: data.ConsumerGroup}
	if data.PartitionInfo != nil {
		info.HasPartition = true
		info.Partition = data.PartitionInfo.Partition
		info.Offset = data.PartitionInfo.Offset
	}
	return info
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
	if trace.Direction == directionRecv {
		reqType = request.EventTypeKafkaServer
	}

	messagingInfo := kafkaMessagingInfo(data)

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

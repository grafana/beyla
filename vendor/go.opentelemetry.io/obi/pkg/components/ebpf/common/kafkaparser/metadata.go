// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kafkaparser

import "errors"

const partitionLen = // 26
Int16Len +           // error_code
	Int32Len + // partition_index
	Int32Len + // leader_id
	Int32Len + // leader_epoch
	Int32Len + // replica_nodes
	Int32Len + // isr_nodes
	Int32Len // offline_replicas

type MetadataTopic struct {
	Name string
	UUID UUID
}

type MetadataResponse struct {
	Topics []*MetadataTopic
}

func ParseMetadataResponse(pkt []byte, header *KafkaRequestHeader, offset int) (*MetadataResponse, error) {
	offset, err := metadataResponseSkipUntilTopics(pkt, header, offset)
	if err != nil {
		return nil, err
	}
	topics, err := parsMetadataTopics(pkt, header, offset)
	if err != nil {
		return nil, err
	}
	if len(topics) == 0 {
		return nil, errors.New("no Topics found in metadata request")
	}
	return &MetadataResponse{
		Topics: topics,
	}, nil
}

func metadataResponseSkipUntilTopics(pkt []byte, header *KafkaRequestHeader, offset Offset) (Offset, error) {
	var err error
	offset, err = skipBytes(pkt, offset, Int32Len) // throttle_time_ms
	if err != nil {
		return 0, err
	}
	offset, err = skipMetadataResponseBrokers(pkt, header, offset)
	if err != nil {
		return 0, err
	}

	clusterIDLen, offset, err := readStringLength(pkt, header, offset, true)
	if err != nil {
		return 0, err
	}
	offset, err = skipBytes(pkt, offset, clusterIDLen+Int32Len) // cluster_id + controller_id
	if err != nil {
		return 0, err
	}
	return offset, nil
}

func skipMetadataResponseBrokers(pkt []byte, header *KafkaRequestHeader, offset Offset) (Offset, error) {
	brokersLen, offset, err := readArrayLength(pkt, header, offset)
	if err != nil {
		return 0, err
	}
	for i := 0; i < brokersLen; i++ {
		offset, err = skipBytes(pkt, offset, Int32Len) // node_id
		if err != nil {
			return 0, err
		}
		var hostLen int
		hostLen, offset, err = readStringLength(pkt, header, offset, false)
		if err != nil {
			return 0, err
		}
		offset, err = skipBytes(pkt, offset, hostLen+Int32Len) // host + port
		if err != nil {
			return 0, err
		}
		var rackLen int
		rackLen, offset, err = readStringLength(pkt, header, offset, true)
		if err != nil {
			return 0, err
		}
		offset, err = skipBytes(pkt, offset, rackLen) // rack
		if err != nil {
			return 0, err
		}
		offset, err = skipTaggedFields(pkt, header, offset)
		if err != nil {
			return 0, err
		}
	}
	return offset, nil
}

func parsMetadataTopics(pkt []byte, header *KafkaRequestHeader, offset int) ([]*MetadataTopic, error) {
	topicsLen, offset, err := readArrayLength(pkt, header, offset)
	if err != nil {
		return nil, err
	}
	var topics []*MetadataTopic
	var topic *MetadataTopic
	for i := 0; i < topicsLen; i++ {
		topic, offset, err = parseMetadataTopic(pkt, header, offset, i == topicsLen-1)
		if err != nil {
			// return the Topics parsed so far, even if one topic failed
			return topics, nil
		}
		if topic != nil {
			topics = append(topics, topic)
		}
	}
	return topics, err
}

func parseMetadataTopic(pkt []byte, header *KafkaRequestHeader, offset int, isLast bool) (*MetadataTopic, int, error) {
	var topic MetadataTopic
	/*
	  Topics => error_code Name topic_id is_internal [partitions] topic_authorized_operations _tagged_fields
	    error_code => INT16
	    Name => COMPACT_STRING / (12+) COMPACT_NULLABLE_STRING
	    topic_id => UUID
	    is_internal => BOOLEAN
	    partitions => error_code partition_index leader_id leader_epoch [replica_nodes] [isr_nodes] [offline_replicas] _tagged_fields
	      error_code => INT16
	      partition_index => INT32
	      leader_id => INT32
	      leader_epoch => INT32
	      replica_nodes => INT32
	      isr_nodes => INT32
	      offline_replicas => INT32
	    topic_authorized_operations => INT32
	*/
	offset, err := skipBytes(pkt, offset, Int16Len) // error_code
	if err != nil {
		return nil, offset, err
	}
	isNullable := header.APIVersion >= 12
	topicName, offset, err := readString(pkt, header, offset, isNullable)
	if err != nil {
		return nil, offset, err
	}
	topic.Name = topicName
	topicUUID, offset, err := readUUID(pkt, offset)
	if err != nil {
		return nil, offset, err
	}
	topic.UUID = *topicUUID
	// optimization: no need to continue reading if this is the last topic
	if isLast {
		return &topic, offset, nil
	}
	partitionsCount, offset, err := readArrayLength(pkt, header, offset)
	if err != nil {
		return nil, offset, err
	}
	offset, err = skipBytes(pkt, offset, (partitionsCount*partitionLen)+ // partitions
		Int32Len, // topic_authorized_operations
	)
	if err != nil {
		// if we can't read partitions, we can still return the topic
		return &topic, offset, nil
	}
	offset, err = skipTaggedFields(pkt, header, offset)
	if err != nil {
		return &topic, offset, nil
	}
	return &topic, offset, nil
}

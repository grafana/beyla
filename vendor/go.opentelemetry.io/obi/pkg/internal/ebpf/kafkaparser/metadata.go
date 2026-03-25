// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kafkaparser // import "go.opentelemetry.io/obi/pkg/internal/ebpf/kafkaparser"

import (
	"errors"

	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

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

func ParseMetadataResponse(r *largebuf.LargeBufferReader, header KafkaRequestHeader) (*MetadataResponse, error) {
	if err := metadataResponseSkipUntilTopics(r, header); err != nil {
		return nil, err
	}
	topics, err := parseMetadataTopics(r, header)
	if err != nil {
		return nil, err
	}
	if len(topics) == 0 {
		return nil, errors.New("no Topics found in metadata response")
	}
	return &MetadataResponse{
		Topics: topics,
	}, nil
}

func metadataResponseSkipUntilTopics(r *largebuf.LargeBufferReader, header KafkaRequestHeader) error {
	if err := r.Skip(Int32Len); err != nil { // throttle_time_ms
		return err
	}
	if err := skipMetadataResponseBrokers(r, header); err != nil {
		return err
	}

	clusterIDLen, err := readStringLength(r, header, true)
	if err != nil {
		return err
	}
	return r.Skip(clusterIDLen + Int32Len) // cluster_id + controller_id
}

func skipMetadataResponseBrokers(r *largebuf.LargeBufferReader, header KafkaRequestHeader) error {
	brokersLen, err := readArrayLength(r, header)
	if err != nil {
		return err
	}
	for range brokersLen {
		if err = r.Skip(Int32Len); err != nil { // node_id
			return err
		}
		var hostLen int
		hostLen, err = readStringLength(r, header, false)
		if err != nil {
			return err
		}
		if err = r.Skip(hostLen + Int32Len); err != nil { // host + port
			return err
		}
		var rackLen int
		rackLen, err = readStringLength(r, header, true)
		if err != nil {
			return err
		}
		if err = r.Skip(rackLen); err != nil { // rack
			return err
		}
		if err = skipTaggedFields(r, header); err != nil {
			return err
		}
	}
	return nil
}

func parseMetadataTopics(r *largebuf.LargeBufferReader, header KafkaRequestHeader) ([]*MetadataTopic, error) {
	topicsLen, err := readArrayLength(r, header)
	if err != nil {
		return nil, err
	}
	var topics []*MetadataTopic
	for i := range topicsLen {
		topic, err := parseMetadataTopic(r, header, i == topicsLen-1)
		if err != nil {
			// return the Topics parsed so far, even if one topic failed
			return topics, nil
		}
		if topic != nil {
			topics = append(topics, topic)
		}
	}
	return topics, nil
}

func parseMetadataTopic(r *largebuf.LargeBufferReader, header KafkaRequestHeader, isLast bool) (*MetadataTopic, error) {
	var topic MetadataTopic
	/*
	  Metadata Response (Version: 10, 11, 12 and 13)
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
	if err := r.Skip(Int16Len); err != nil { // error_code
		return nil, err
	}
	isNullable := header.APIVersion() >= 12
	topicName, err := readString(r, header, isNullable)
	if err != nil {
		return nil, err
	}
	topic.Name = topicName
	topicUUID, err := readUUID(r)
	if err != nil {
		return nil, err
	}
	topic.UUID = *topicUUID
	// optimization: no need to continue reading if this is the last topic
	if isLast {
		return &topic, nil
	}
	partitionsCount, err := readArrayLength(r, header)
	if err != nil {
		return nil, err
	}
	skipBytes := partitionsCount*partitionLen + // partitions
		Int32Len // topic_authorized_operations
	if err = r.Skip(skipBytes); err != nil {
		// if we can't read partitions, we can still return the topic
		return &topic, nil
	}
	if err = skipTaggedFields(r, header); err != nil {
		return &topic, nil
	}
	return &topic, nil
}

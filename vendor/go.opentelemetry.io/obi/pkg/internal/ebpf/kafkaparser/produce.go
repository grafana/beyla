// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kafkaparser // import "go.opentelemetry.io/obi/pkg/internal/ebpf/kafkaparser"

import (
	"errors"

	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

type ProduceTopic struct {
	Name      string
	UUID      *UUID
	Partition *int
}

type ProduceRequest struct {
	Topics []*ProduceTopic
}

func ParseProduceRequest(r *largebuf.LargeBufferReader, header KafkaRequestHeader) (*ProduceRequest, error) {
	if err := produceRequestSkipUntilTopics(r, header); err != nil {
		return nil, err
	}
	topics, err := parseProduceTopics(r, header)
	if err != nil {
		return nil, err
	}
	if len(topics) == 0 {
		return nil, errors.New("no Topics found in produce request")
	}
	return &ProduceRequest{
		Topics: topics,
	}, nil
}

func produceRequestSkipUntilTopics(r *largebuf.LargeBufferReader, header KafkaRequestHeader) error {
	/*
		Produce Request (Version: 3+) => transactional_id acks timeout_ms [topic_data] _tagged_fields
		  transactional_id => NULLABLE_STRING (v3-8) / COMPACT_NULLABLE_STRING (v9+)
		  acks => INT16
		  timeout_ms => INT32
		  topic_data => Name (v3-12) / TopicId UUID (v13+) [partition_data] _tagged_fields
	*/
	transactionIDSize, err := readStringLength(r, header, true)
	if err != nil {
		return err
	}
	return r.Skip(
		transactionIDSize + // transactional_id
			Int16Len + // acks
			Int32Len, // timeout_ms
	)
}

func parseProduceTopics(r *largebuf.LargeBufferReader, header KafkaRequestHeader) ([]*ProduceTopic, error) {
	topicsLen, err := readArrayLength(r, header)
	if err != nil {
		return nil, err
	}
	var topics []*ProduceTopic
	if topicsLen <= 0 {
		return topics, nil
	}
	// read single topic for now, because skipping records is complicated
	topic, err := parseProduceTopic(r, header)
	if err != nil {
		// return the Topics parsed so far, even if one topic failed
		return topics, nil
	}
	if topic != nil {
		topics = append(topics, topic)
	}
	return topics, nil
}

func parseProduceTopic(r *largebuf.LargeBufferReader, header KafkaRequestHeader) (*ProduceTopic, error) {
	var topic ProduceTopic
	if header.APIVersion() >= 13 {
		// v13+: topic identified by UUID (KIP-516), name resolved from metadata cache by caller
		// https://cwiki.apache.org/confluence/display/KAFKA/KIP-516%3A+Topic+Identifiers#KIP516:TopicIdentifiers-ProduceRequestv9
		uuid, err := readUUID(r)
		if err != nil {
			return nil, err
		}
		topic.UUID = uuid
	} else {
		/*
		  Topics => topic [partitions] _tagged_fields
		    topic => STRING (v3-8) / COMPACT_STRING (v9-12)
		*/
		topicName, err := readString(r, header, false)
		if err != nil {
			return nil, err
		}
		topic.Name = topicName
	}
	partitionsLen, err := readArrayLength(r, header)
	if err != nil {
		// return the topic even if partitions can't be read
		return &topic, nil
	}
	if partitionsLen != 1 {
		// if more than 1 Partition, we just won't report Partition
		return &topic, nil
	}
	// read single Partition for now, because skipping records is complicated
	firstPartition, err := readInt32(r)
	if err != nil {
		return &topic, nil
	}
	topic.Partition = &firstPartition
	return &topic, nil
}

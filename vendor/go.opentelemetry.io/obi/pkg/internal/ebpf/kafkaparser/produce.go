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

const maxProduceTopics = 100

var (
	errInvalidProduceRecordsLength = errors.New("invalid produce records length")
	errNoTopicsInProduce           = errors.New("no Topics found in produce request")
)

func ParseProduceRequest(r *largebuf.LargeBufferReader, header KafkaRequestHeader) (*ProduceRequest, error) {
	if err := produceRequestSkipUntilTopics(r, header); err != nil {
		return nil, err
	}
	topics, err := parseProduceTopics(r, header)
	if err != nil {
		return nil, err
	}
	if len(topics) == 0 {
		return nil, errNoTopicsInProduce
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
	if topicsLen <= 0 {
		return nil, nil
	}
	if topicsLen > maxProduceTopics {
		topicsLen = maxProduceTopics
	}

	var topics []*ProduceTopic
	for range topicsLen {
		topic, err := parseProduceTopic(r, header)
		if err != nil {
			return topics, nil
		}
		if topic != nil {
			topics = append(topics, topic)
		}
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
	for i := range partitionsLen {
		partition, perr := parseProducePartition(r, header)
		if i == 0 {
			topic.Partition = &partition
		}
		if perr != nil {
			return &topic, nil
		}
	}
	if err = skipTaggedFields(r, header); err != nil {
		return &topic, nil
	}
	return &topic, nil
}

func parseProducePartition(r *largebuf.LargeBufferReader, header KafkaRequestHeader) (int, error) {
	partition, err := readInt32(r)
	if err != nil {
		return 0, err
	}
	if err = skipProduceRecords(r, header); err != nil {
		return partition, err
	}
	if err = skipTaggedFields(r, header); err != nil {
		return partition, err
	}
	return partition, nil
}

func skipProduceRecords(r *largebuf.LargeBufferReader, header KafkaRequestHeader) error {
	if isFlexible(header) {
		recordsLen, err := readUnsignedVarint(r)
		if err != nil {
			return err
		}
		if recordsLen == 0 {
			return nil
		}
		return r.Skip(recordsLen - 1)
	}

	recordsLen, err := readInt32(r)
	if err != nil {
		return err
	}
	if recordsLen == -1 {
		return nil
	}
	if recordsLen < 0 {
		return errInvalidProduceRecordsLength
	}
	return r.Skip(recordsLen)
}

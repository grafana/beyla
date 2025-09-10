// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kafkaparser

import "errors"

type ProduceTopic struct {
	Name      string
	Partition *int
}

type ProduceRequest struct {
	Topics []*ProduceTopic
}

func ParseProduceRequest(pkt []byte, header *KafkaRequestHeader, offset Offset) (*ProduceRequest, error) {
	offset, err := produceRequestSkipUntilTopics(pkt, header, offset)
	if err != nil {
		return nil, err
	}
	topics, err := parseProduceTopics(pkt, header, offset)
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

func produceRequestSkipUntilTopics(pkt []byte, header *KafkaRequestHeader, offset Offset) (Offset, error) {
	/*
		Produce Request (Version: 3-12) => transactional_id acks timeout_ms [topic_data] _tagged_fields
		  transactional_id => NULLABLE_STRING / COMPACT_NULLABLE_STRING
		  acks => INT16
		  timeout_ms => INT32
		  topic_data => Name [partition_data] _tagged_fields
	*/
	transactionIDSize, offset, err := readStringLength(pkt, header, offset, true)
	if err != nil {
		return 0, err
	}
	offset, err = skipBytes(pkt, offset,
		transactionIDSize+ // transactional_id
			Int16Len+ // acks
			Int32Len, // timeout_ms
	)
	if err != nil {
		return 0, err
	}
	return offset, nil
}

func parseProduceTopics(pkt []byte, header *KafkaRequestHeader, offset Offset) ([]*ProduceTopic, error) {
	topicsLen, offset, err := readArrayLength(pkt, header, offset)
	if err != nil {
		return nil, err
	}
	var topics []*ProduceTopic
	var topic *ProduceTopic
	// parse each topic
	if topicsLen <= 0 {
		return topics, nil
	}
	// read single topic for now, because skipping records is complicated
	topic, _, err = parseProduceTopic(pkt, header, offset)
	if err != nil {
		// return the Topics parsed so far, even if one topic failed
		return topics, nil
	}
	if topic != nil {
		topics = append(topics, topic)
	}
	return topics, err
}

func parseProduceTopic(pkt []byte, header *KafkaRequestHeader, offset Offset) (*ProduceTopic, Offset, error) {
	var topic ProduceTopic
	/*
	  Topics => topic [partitions] _tagged_fields
	    topic => STRING / COMPACT_STRING
	*/
	topicName, offset, err := readString(pkt, header, offset, false)
	if err != nil {
		return nil, offset, err
	}
	topic.Name = topicName
	partitionsLen, offset, err := readArrayLength(pkt, header, offset)
	if err != nil {
		// return the topic even if partitions can't be read
		return &topic, offset, nil
	}
	if partitionsLen != 1 {
		// if more then 1 Partition, we just won't report Partition
		return &topic, offset, nil
	}
	// read single Partition for now, because skipping records is complicated
	firstPartition, offset, err := readInt32(pkt, offset)
	if err != nil {
		return &topic, offset, nil
	}
	topic.Partition = &firstPartition
	return &topic, offset, nil
}

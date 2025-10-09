// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kafkaparser

import "errors"

type FetchPartition struct {
	Partition   int
	FetchOffset int64
}
type FetchTopic struct {
	Name      string
	UUID      *UUID
	Partition *FetchPartition
}

type FetchRequest struct {
	Topics []*FetchTopic
}

func ParseFetchRequest(pkt []byte, header *KafkaRequestHeader, offset Offset) (*FetchRequest, error) {
	offset, err := fetchRequestSkipUntilTopics(pkt, header, offset)
	if err != nil {
		return nil, err
	}
	if offset >= len(pkt) {
		return nil, errors.New("offset exceeds packet size")
	}
	topics, err := parseFetchTopics(pkt, header, offset)
	if err != nil {
		return nil, err
	}
	if len(topics) == 0 {
		return nil, errors.New("no Topics found in fetch request")
	}
	return &FetchRequest{
		Topics: topics,
	}, nil
}

func fetchRequestSkipUntilTopics(pkt []byte, header *KafkaRequestHeader, offset Offset) (Offset, error) {
	var err error
	switch {
	case header.APIVersion >= 15:
		/*
			Fetch Request (Version: 15-17) => max_wait_ms min_bytes max_bytes isolation_level session_id session_epoch ...
			  max_wait_ms => INT32
			  min_bytes => INT32
			  max_bytes => INT32
			  isolation_level => INT8
			  session_id => INT32
			  session_epoch => INT32
			  Topics => ...
		*/
		offset, err = skipBytes(pkt, offset,
			Int32Len+ // max_wait_ms
				Int32Len+ // min_bytes
				Int32Len+ // max_bytes
				Int8Len+ // isolation_level
				Int32Len+ // session_id
				Int32Len, // session_epoch
		)
	case header.APIVersion >= 7:
		/*
				Fetch Request (Version: 7-14) => replica_id max_wait_ms min_bytes max_bytes isolation_level session_id session_epoch ...
				  replica_id => INT32
			      max_wait_ms => INT32
				  min_bytes => INT32
				  max_bytes => INT32
				  isolation_level => INT8
				  session_id => INT32
				  session_epoch => INT32
				  Topics => ...
		*/
		offset, err = skipBytes(pkt, offset,
			Int32Len+ // replica_id
				Int32Len+ // max_wait_ms
				Int32Len+ // min_bytes
				Int32Len+ // max_bytes
				Int8Len+ // isolation_level
				Int32Len+ // session_id
				Int32Len, // session_epoch
		)

	case header.APIVersion >= 4:
		/*
			Fetch Request (Version: 4-6) => replica_id max_wait_ms min_bytes max_bytes isolation_level [Topics]
			  replica_id => INT32
			  max_wait_ms => INT32
			  min_bytes => INT32
			  max_bytes => INT32
			  isolation_level => INT8
			  Topics => ...
		*/
		offset, err = skipBytes(pkt, offset,
			Int32Len+ // replica_id
				Int32Len+ // max_wait_ms
				Int32Len+ // min_bytes
				Int32Len+ // max_bytes
				Int8Len, // isolation_level
		)
	}
	if err != nil {
		return 0, err
	}
	return offset, nil
}

func parseFetchTopics(pkt []byte, header *KafkaRequestHeader, offset Offset) ([]*FetchTopic, error) {
	topicsLen, offset, err := readArrayLength(pkt, header, offset)
	if err != nil {
		return nil, err
	}
	var topics []*FetchTopic
	var topic *FetchTopic
	for i := 0; i < topicsLen; i++ {
		topic, offset, err = parseFetchTopic(pkt, header, offset)
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

func parseFetchTopic(pkt []byte, header *KafkaRequestHeader, offset Offset) (*FetchTopic, Offset, error) {
	var topic FetchTopic
	var err error
	if header.APIVersion >= 13 {
		/*
		  since kafka fetch request version 13, Topics are identified by a UUID and not by Name.
		  correlation between topic Name and UUID is done by the metadata response.

		  Topics => topic_id [partitions] _tagged_fields
		    topic_id => UUID
		*/
		var topicUUID *UUID
		topicUUID, offset, err = readUUID(pkt, offset)
		if err != nil {
			return nil, offset, err
		}
		topic.UUID = topicUUID
	} else {
		/*
		  Topics => topic [partitions] _tagged_fields
		    topic => STRING / COMPACT_STRING
		*/
		var topicName string
		topicName, offset, err = readString(pkt, header, offset, false)
		if err != nil {
			return nil, offset, err
		}
		topic.Name = topicName
	}
	partitionCount, offset, err := readArrayLength(pkt, header, offset)
	if err != nil {
		// if we fail to read Partition count, we can still return the topic
		return &topic, offset, nil
	}
	if partitionCount != 1 {
		// no need to capture multiple partitions for fetch request, if its 1 Partition we can add it to the span
		offset, err = skipFetchPartitions(pkt, header, offset, partitionCount)
		if err != nil {
			// if we fail to skip partitions, we can still return the topic
			return &topic, offset, nil
		}
	} else {
		var partition *FetchPartition
		partition, offset, err = parseFetchPartition(pkt, header, offset)
		if err != nil {
			// if we fail to parse Partition, we can still return the topic
			return &topic, offset, nil
		}
		topic.Partition = partition
	}
	offset, err = skipTaggedFields(pkt, header, offset)
	if err != nil {
		return &topic, offset, nil
	}
	return &topic, offset, nil
}

func parseFetchPartition(pkt []byte, header *KafkaRequestHeader, offset Offset) (*FetchPartition, Offset, error) {
	/*
	   partitions => Partition fetch_offset log_start_offset partition_max_bytes
	     Partition => INT32
	     fetch_offset => INT64
	*/
	partition, offset, err := readInt32(pkt, offset)
	if err != nil {
		return nil, offset, err
	}
	if header.APIVersion >= 9 {
		/*
				fetch request version 9 and above include current_leader_epoch between Partition and fetch_offset.
			    partitions => Partition current_leader_epoch fetch_offset last_fetched_epoch log_start_offset partition_max_bytes _tagged_fields
			      Partition => INT32
			      current_leader_epoch => INT32
			      fetch_offset => INT64
		*/
		offset, err = skipBytes(pkt, offset, Int32Len) // current_leader_epoch
		if err != nil {
			return nil, offset, err
		}
	}
	fetchOffset, offset, err := readInt64(pkt, offset)
	if err != nil {
		return nil, offset, err
	}
	return &FetchPartition{
		Partition:   partition,
		FetchOffset: fetchOffset,
	}, offset, nil
}

func skipFetchPartitions(pkt []byte, header *KafkaRequestHeader, offset Offset, partitionCount int) (Offset, error) {
	var fetchPartitionLen int
	switch {
	case header.APIVersion >= 12:
		/*
		   partitions => Partition current_leader_epoch fetch_offset last_fetched_epoch log_start_offset partition_max_bytes _tagged_fields
		     Partition => INT32
		     current_leader_epoch => INT32
		     fetch_offset => INT64
		     last_fetched_epoch => INT32
		     log_start_offset => INT64
		     partition_max_bytes => INT32
		*/
		fetchPartitionLen = Int32Len + // Partition
			Int32Len + // current_leader_epoch
			Int64Len + // fetch_offset
			Int32Len + // last_fetched_epoch
			Int64Len + // log_start_offset
			Int32Len // partition_max_bytes
	case header.APIVersion >= 9:
		/*
		   partitions => Partition current_leader_epoch fetch_offset log_start_offset partition_max_bytes
		     Partition => INT32
		     current_leader_epoch => INT32
		     fetch_offset => INT64
		     log_start_offset => INT64
		     partition_max_bytes => INT32
		*/
		fetchPartitionLen = Int32Len + // Partition
			Int32Len + // current_leader_epoch
			Int64Len + // fetch_offset
			Int64Len + // log_start_offset
			Int32Len // partition_max_bytes
	case header.APIVersion >= 5:
		/*
		   partitions => Partition fetch_offset log_start_offset partition_max_bytes
		     Partition => INT32
		     fetch_offset => INT64
		     log_start_offset => INT64
		     partition_max_bytes => INT32
		*/
		fetchPartitionLen = Int32Len + // Partition
			Int64Len + // fetch_offset
			Int64Len + // log_start_offset
			Int32Len // partition_max_bytes
	default:
		/*
		   partitions => Partition fetch_offset partition_max_bytes
		     Partition => INT32
		     fetch_offset => INT64
		     partition_max_bytes => INT32
		*/
		fetchPartitionLen = Int32Len + // Partition
			Int64Len + // fetch_offset
			Int32Len // partition_max_bytes
	}
	offset, err := skipBytes(pkt, offset, fetchPartitionLen*partitionCount)
	if err != nil {
		return 0, err
	}
	return offset, nil
}

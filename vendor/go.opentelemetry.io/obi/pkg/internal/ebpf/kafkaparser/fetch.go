// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kafkaparser // import "go.opentelemetry.io/obi/pkg/internal/ebpf/kafkaparser"

import (
	"errors"

	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

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

var (
	errOffsetExceedsPacketSize = errors.New("offset exceeds packet size")
	errNoTopics                = errors.New("no Topics found in fetch request")
)

func ParseFetchRequest(r *largebuf.LargeBufferReader, header KafkaRequestHeader) (*FetchRequest, error) {
	if err := fetchRequestSkipUntilTopics(r, header); err != nil {
		return nil, err
	}
	if r.Remaining() == 0 {
		return nil, errOffsetExceedsPacketSize
	}
	topics, err := parseFetchTopics(r, header)
	if err != nil {
		return nil, err
	}
	if len(topics) == 0 {
		return nil, errNoTopics
	}
	return &FetchRequest{
		Topics: topics,
	}, nil
}

func fetchRequestSkipUntilTopics(r *largebuf.LargeBufferReader, header KafkaRequestHeader) error {
	var skipLen int
	switch {
	case header.APIVersion() >= 15:
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
		skipLen = Int32Len + // max_wait_ms
			Int32Len + // min_bytes
			Int32Len + // max_bytes
			Int8Len + // isolation_level
			Int32Len + // session_id
			Int32Len // session_epoch
	case header.APIVersion() >= 7:
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
		skipLen = Int32Len + // replica_id
			Int32Len + // max_wait_ms
			Int32Len + // min_bytes
			Int32Len + // max_bytes
			Int8Len + // isolation_level
			Int32Len + // session_id
			Int32Len // session_epoch

	case header.APIVersion() >= 4:
		/*
			Fetch Request (Version: 4-6) => replica_id max_wait_ms min_bytes max_bytes isolation_level [Topics]
			  replica_id => INT32
			  max_wait_ms => INT32
			  min_bytes => INT32
			  max_bytes => INT32
			  isolation_level => INT8
			  Topics => ...
		*/
		skipLen = Int32Len + // replica_id
			Int32Len + // max_wait_ms
			Int32Len + // min_bytes
			Int32Len + // max_bytes
			Int8Len // isolation_level
	}
	if skipLen > 0 {
		return r.Skip(skipLen)
	}
	return nil
}

func parseFetchTopics(r *largebuf.LargeBufferReader, header KafkaRequestHeader) ([]*FetchTopic, error) {
	topicsLen, err := readArrayLength(r, header)
	if err != nil {
		return nil, err
	}
	var topics []*FetchTopic
	for range topicsLen {
		topic, err := parseFetchTopic(r, header)
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

func parseFetchTopic(r *largebuf.LargeBufferReader, header KafkaRequestHeader) (*FetchTopic, error) {
	var topic FetchTopic
	var err error
	if header.APIVersion() >= 13 {
		/*
		  since kafka fetch request version 13, Topics are identified by a UUID and not by Name.
		  correlation between topic Name and UUID is done by the metadata response.

		  Topics => topic_id [partitions] _tagged_fields
		    topic_id => UUID
		*/
		var topicUUID *UUID
		topicUUID, err = readUUID(r)
		if err != nil {
			return nil, err
		}
		topic.UUID = topicUUID
	} else {
		/*
		  Topics => topic [partitions] _tagged_fields
		    topic => STRING / COMPACT_STRING
		*/
		var topicName string
		topicName, err = readString(r, header, false)
		if err != nil {
			return nil, err
		}
		topic.Name = topicName
	}
	partitionCount, err := readArrayLength(r, header)
	if err != nil {
		// if we fail to read Partition count, we can still return the topic
		return &topic, nil
	}
	// Walk every partition so the reader stays aligned for the next topic. We only
	// keep the first partition for the span, but each entry MUST be fully consumed
	// (including its trailing fields and per-partition tagged fields); otherwise a
	// multi-topic Fetch request mis-parses every topic after the first.
	for i := range partitionCount {
		partition, fetchOffset, perr := parseFetchPartition(r, header)
		if perr != nil {
			// if we fail to parse a Partition, we can still return the topic
			return &topic, nil
		}
		// Only the first partition is kept for the span; the rest are parsed
		// solely to advance the reader (a topic can have many partitions, e.g. 47),
		// so allocate a FetchPartition for the first entry only.
		if i == 0 {
			topic.Partition = &FetchPartition{
				Partition:   partition,
				FetchOffset: fetchOffset,
			}
		}
	}
	if err = skipTaggedFields(r, header); err != nil {
		return &topic, nil
	}
	return &topic, nil
}

// parseFetchPartition reads one partition entry, advancing the reader past the
// entire entry (including version-specific fields and flexible tagged fields).
//
// partitions => partition current_leader_epoch(9+) fetch_offset last_fetched_epoch(12+) log_start_offset(5+) partition_max_bytes _tagged_fields(12+)
func parseFetchPartition(r *largebuf.LargeBufferReader, header KafkaRequestHeader) (partition int, fetchOffset int64, err error) {
	partition, err = readInt32(r)
	if err != nil {
		return 0, 0, err
	}
	if header.APIVersion() >= 9 {
		if err = r.Skip(Int32Len); err != nil { // current_leader_epoch
			return 0, 0, err
		}
	}
	fetchOffset, err = readInt64(r)
	if err != nil {
		return 0, 0, err
	}
	// Skip the remaining fixed fields of this partition; the set is version-dependent.
	switch {
	case header.APIVersion() >= 12:
		// last_fetched_epoch(INT32) log_start_offset(INT64) partition_max_bytes(INT32)
		if err = r.Skip(Int32Len + Int64Len + Int32Len); err != nil {
			return 0, 0, err
		}
	case header.APIVersion() >= 5:
		// log_start_offset(INT64) partition_max_bytes(INT32)
		if err = r.Skip(Int64Len + Int32Len); err != nil {
			return 0, 0, err
		}
	default:
		// partition_max_bytes(INT32)
		if err = r.Skip(Int32Len); err != nil {
			return 0, 0, err
		}
	}
	// per-partition tagged fields (flexible versions only; no-op otherwise)
	if err = skipTaggedFields(r, header); err != nil {
		return 0, 0, err
	}
	return partition, fetchOffset, nil
}

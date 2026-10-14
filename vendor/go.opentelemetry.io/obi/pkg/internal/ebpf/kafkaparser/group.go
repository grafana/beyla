// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kafkaparser // import "go.opentelemetry.io/obi/pkg/internal/ebpf/kafkaparser"

import (
	"encoding/binary"
	"errors"
	"unicode/utf8"

	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

// GroupTopic is a topic referenced by a group request, by name or (KIP-516) by UUID.
type GroupTopic struct {
	Name string
	UUID *UUID
}

// GroupRequest is the consumer-group view of a group-coordination or offset
// request: the group id, plus the topics the request mentions when it carries any.
type GroupRequest struct {
	GroupID string
	// MemberID identifies the sending member within the group, "" until the coordinator
	// assigned one (a first JoinGroup) and in the requests that do not carry it.
	MemberID string
	// Members is set by LeaveGroup only: the members removed from the group, the
	// sender itself or, from the admin client, any member of any group.
	Members []string
	Topics  []*GroupTopic
	// MemberEpoch is set by ConsumerGroupHeartbeat only (0 otherwise): a negative epoch
	// is a leave, see LeaveGroupMemberEpoch and LeaveGroupStaticMemberEpoch.
	MemberEpoch int
	// ProtocolType is the group protocol named by JoinGroup and SyncGroup v5+ ("" when the
	// request carries none). Only ConsumerProtocolType groups are consumer groups: Kafka
	// Connect ("connect") and Schema Registry ("sr") coordinate through the same APIs.
	ProtocolType string
	// Subscription reports that Topics is the member's complete subscription (a JoinGroup
	// or ConsumerGroupHeartbeat whose topic list was captured in full), replacing what was
	// learned before, rather than the topics one request happened to touch.
	Subscription bool
}

const (
	maxGroupTopics     = 100
	maxGroupPartitions = 1024
	maxGroupMembers    = 100

	// ConsumerGroupHeartbeat member epochs that end the membership (KIP-848,
	// ConsumerGroupHeartbeatRequest.LEAVE_GROUP_MEMBER_EPOCH / LEAVE_GROUP_STATIC_MEMBER_EPOCH).
	LeaveGroupMemberEpoch       = -1
	LeaveGroupStaticMemberEpoch = -2

	// ConsumerProtocolType is the JoinGroup protocol_type of consumers (ConsumerProtocol.PROTOCOL_TYPE).
	ConsumerProtocolType = "consumer"
)

var (
	errKafkaInvalidGroupID         = errors.New("invalid group id")
	errKafkaInvalidPrintableString = errors.New("string is not printable UTF-8")
)

// ParseGroupRequest parses the body of a group-coordination or offset request.
// Only the group id is mandatory: the kernel forwards a bounded prefix of every
// request, so the topic list may be cut and is returned as far as it was read.
func ParseGroupRequest(r *largebuf.LargeBufferReader, header KafkaRequestHeader) (*GroupRequest, error) {
	switch header.APIKey() {
	case APIKeyJoinGroup:
		return parseJoinGroup(r, header)
	case APIKeyOffsetCommit:
		return parseOffsetCommit(r, header)
	case APIKeyOffsetFetch:
		return parseOffsetFetch(r, header)
	case APIKeyConsumerGroupHeartbeat:
		return parseConsumerGroupHeartbeat(r, header)
	case APIKeySyncGroup:
		return parseSyncGroup(r, header)
	case APIKeyHeartbeat:
		return parseHeartbeat(r, header)
	case APIKeyLeaveGroup:
		return parseLeaveGroup(r, header)
	default:
		return nil, errKafkaReqUnsupportedAPIKey
	}
}

/*
JoinGroup Request (Version: 0-9) => group_id session_timeout_ms rebalance_timeout_ms member_id group_instance_id protocol_type [protocols] reason _tagged_fields

	group_id => STRING / COMPACT_STRING
	session_timeout_ms => INT32
	rebalance_timeout_ms => INT32 (1+)
	member_id => STRING / COMPACT_STRING (empty on the first join)
	group_instance_id => NULLABLE_STRING (5+)
	protocol_type => STRING / COMPACT_STRING
	protocols => name metadata _tagged_fields
	  name => STRING / COMPACT_STRING
	  metadata => BYTES / COMPACT_BYTES (ConsumerProtocolSubscription when protocol_type == "consumer")
*/
func parseJoinGroup(r *largebuf.LargeBufferReader, header KafkaRequestHeader) (*GroupRequest, error) {
	groupID, err := readGroupID(r, header)
	if err != nil {
		return nil, err
	}
	req := &GroupRequest{GroupID: groupID}

	skipLen := Int32Len // session_timeout_ms
	if header.APIVersion() >= 1 {
		skipLen += Int32Len // rebalance_timeout_ms
	}
	if err = r.Skip(skipLen); err != nil {
		return req, nil
	}
	if req.MemberID, err = readPrintableString(r, header); err != nil {
		return req, nil
	}
	if header.APIVersion() >= 5 {
		if err = skipString(r, header); err != nil { // group_instance_id
			return req, nil
		}
	}
	if req.ProtocolType, err = readPrintableString(r, header); err != nil || req.ProtocolType != ConsumerProtocolType {
		return req, nil
	}
	protocolsLen, err := readArrayLength(r, header)
	if err != nil || protocolsLen == 0 {
		return req, nil
	}
	// Every protocol entry lists the same subscription: the first one is enough.
	if err = skipString(r, header); err != nil { // protocols[0].name
		return req, nil
	}
	metadataLen, err := readBytesLength(r, header)
	if err != nil {
		return req, nil
	}
	// Parse the metadata through a reader bounded to the payload (or to what the kernel
	// captured of it), so a wrong length can never turn the following request fields
	// into topic names.
	start := r.ReadOffset()
	metadata, err := header.lb.NewLimitedReader(start, start+min(metadataLen, r.Remaining()))
	if err != nil {
		return req, nil
	}
	req.Topics, req.Subscription = parseConsumerSubscriptionTopics(&metadata)
	return req, nil
}

// parseConsumerSubscriptionTopics reads the topics of a ConsumerProtocolSubscription
// payload from a reader bounded to that payload, reporting whether the whole list was
// read. The payload has its own non-flexible encoding regardless of the enclosing
// request version:
//
//	version => INT16
//	topics => INT32 count, STRING each
//	(user_data, owned_partitions, ... not read)
func parseConsumerSubscriptionTopics(r *largebuf.LargeBufferReader) ([]*GroupTopic, bool) {
	if _, err := readInt16(r); err != nil { // version
		return nil, false
	}
	count, err := readInt32(r)
	if err != nil {
		return nil, false
	}
	complete := count >= 0 && count <= maxGroupTopics
	var topics []*GroupTopic
	for range min(count, maxGroupTopics) {
		size, err := readInt16(r)
		if err != nil || size < 1 {
			return topics, false
		}
		name, err := readValidatedString(r, size)
		if err != nil {
			return topics, false
		}
		topics = append(topics, &GroupTopic{Name: name})
	}
	return topics, complete
}

/*
SyncGroup Request (Version: 0-5) => group_id generation_id member_id group_instance_id protocol_type protocol_name [assignments] _tagged_fields

	group_id => STRING / COMPACT_STRING
	generation_id => INT32
	member_id => STRING / COMPACT_STRING
	group_instance_id => NULLABLE_STRING (3+)
	protocol_type => NULLABLE_STRING (5+)
*/
func parseSyncGroup(r *largebuf.LargeBufferReader, header KafkaRequestHeader) (*GroupRequest, error) {
	groupID, err := readGroupID(r, header)
	if err != nil {
		return nil, err
	}
	req := &GroupRequest{GroupID: groupID}

	if err = r.Skip(Int32Len); err != nil { // generation_id
		return req, nil
	}
	if req.MemberID, err = readPrintableString(r, header); err != nil {
		return req, nil
	}
	if header.APIVersion() < 5 {
		return req, nil
	}
	if err = skipString(r, header); err != nil { // group_instance_id
		return req, nil
	}
	if req.ProtocolType, err = readPrintableString(r, header); err != nil {
		req.ProtocolType = ""
	}
	return req, nil
}

/*
Heartbeat Request (Version: 0-4) => group_id generation_id member_id group_instance_id _tagged_fields

	group_id => STRING / COMPACT_STRING
	generation_id => INT32
	member_id => STRING / COMPACT_STRING
*/
func parseHeartbeat(r *largebuf.LargeBufferReader, header KafkaRequestHeader) (*GroupRequest, error) {
	groupID, err := readGroupID(r, header)
	if err != nil {
		return nil, err
	}
	req := &GroupRequest{GroupID: groupID}

	if err = r.Skip(Int32Len); err != nil { // generation_id
		return req, nil
	}
	if req.MemberID, err = readPrintableString(r, header); err != nil {
		return req, nil
	}
	return req, nil
}

/*
LeaveGroup Request (Version: 0-5) => group_id member_id [members] _tagged_fields

	group_id => STRING / COMPACT_STRING
	member_id => STRING (0-2)
	members => member_id group_instance_id reason _tagged_fields (3+)
	  member_id => STRING / COMPACT_STRING
	  group_instance_id => NULLABLE_STRING / COMPACT_NULLABLE_STRING
	  reason => NULLABLE_STRING / COMPACT_NULLABLE_STRING (5+)
*/
func parseLeaveGroup(r *largebuf.LargeBufferReader, header KafkaRequestHeader) (*GroupRequest, error) {
	groupID, err := readGroupID(r, header)
	if err != nil {
		return nil, err
	}
	req := &GroupRequest{GroupID: groupID}

	if header.APIVersion() < 3 {
		memberID, err := readPrintableString(r, header)
		if err != nil {
			return req, nil
		}
		req.Members = []string{memberID}
		return req, nil
	}
	membersLen, err := readArrayLength(r, header)
	if err != nil {
		return req, nil
	}
	for range min(membersLen, maxGroupMembers) {
		memberID, err := readPrintableString(r, header)
		if err != nil {
			return req, nil
		}
		req.Members = append(req.Members, memberID)
		if err = skipString(r, header); err != nil { // group_instance_id
			return req, nil
		}
		if header.APIVersion() >= 5 {
			if err = skipString(r, header); err != nil { // reason
				return req, nil
			}
		}
		if err = skipTaggedFields(r, header); err != nil {
			return req, nil
		}
	}
	return req, nil
}

/*
OffsetCommit Request (Version: 2-10) => group_id generation_id_or_member_epoch member_id group_instance_id retention_time_ms [topics] _tagged_fields

	group_id => STRING / COMPACT_STRING
	generation_id_or_member_epoch => INT32
	member_id => STRING / COMPACT_STRING
	group_instance_id => NULLABLE_STRING (7+)
	retention_time_ms => INT64 (2-4)
	topics => name topic_id [partitions] _tagged_fields
	  name => STRING / COMPACT_STRING (0-9)
	  topic_id => UUID (10+)
	  partitions => partition_index committed_offset committed_leader_epoch committed_metadata _tagged_fields
	    partition_index => INT32
	    committed_offset => INT64
	    committed_leader_epoch => INT32 (6+)
	    committed_metadata => NULLABLE_STRING
*/
func parseOffsetCommit(r *largebuf.LargeBufferReader, header KafkaRequestHeader) (*GroupRequest, error) {
	groupID, err := readGroupID(r, header)
	if err != nil {
		return nil, err
	}
	req := &GroupRequest{GroupID: groupID}

	if err = r.Skip(Int32Len); err != nil { // generation_id_or_member_epoch
		return req, nil
	}
	if req.MemberID, err = readPrintableString(r, header); err != nil {
		return req, nil
	}
	if header.APIVersion() >= 7 {
		if err = skipString(r, header); err != nil { // group_instance_id
			return req, nil
		}
	}
	if header.APIVersion() <= 4 {
		if err = r.Skip(Int64Len); err != nil { // retention_time_ms
			return req, nil
		}
	}
	req.Topics = parseGroupTopics(r, header, header.APIVersion() >= 10, skipOffsetCommitPartition)
	return req, nil
}

func skipOffsetCommitPartition(r *largebuf.LargeBufferReader, header KafkaRequestHeader) error {
	skipLen := Int32Len + Int64Len // partition_index, committed_offset
	if header.APIVersion() >= 6 {
		skipLen += Int32Len // committed_leader_epoch
	}
	if err := r.Skip(skipLen); err != nil {
		return err
	}
	if err := skipString(r, header); err != nil { // committed_metadata
		return err
	}
	return skipTaggedFields(r, header)
}

/*
OffsetFetch Request (Version: 1-7) => group_id [topics] require_stable _tagged_fields

	group_id => STRING / COMPACT_STRING
	topics => name [partition_indexes] _tagged_fields (nullable 2+)
	require_stable => BOOLEAN (7+)

OffsetFetch Request (Version: 8-10) => [groups] require_stable _tagged_fields

	groups => group_id member_id member_epoch [topics] _tagged_fields
	  group_id => COMPACT_STRING
	  member_id => COMPACT_NULLABLE_STRING (9+)
	  member_epoch => INT32 (9+)
	  topics => name topic_id [partition_indexes] _tagged_fields (nullable)
	    name => COMPACT_STRING (8-9)
	    topic_id => UUID (10+)
*/
func parseOffsetFetch(r *largebuf.LargeBufferReader, header KafkaRequestHeader) (*GroupRequest, error) {
	if header.APIVersion() >= 8 {
		groupsLen, err := readArrayLength(r, header)
		if err != nil {
			return nil, err
		}
		if groupsLen == 0 {
			return nil, errKafkaInvalidGroupID
		}
	}
	groupID, err := readGroupID(r, header)
	if err != nil {
		return nil, err
	}
	req := &GroupRequest{GroupID: groupID}

	if header.APIVersion() >= 9 {
		if req.MemberID, err = readPrintableString(r, header); err != nil {
			return req, nil
		}
		if err = r.Skip(Int32Len); err != nil { // member_epoch
			return req, nil
		}
	}
	req.Topics = parseGroupTopics(r, header, header.APIVersion() >= 10, skipInt32)
	return req, nil
}

/*
ConsumerGroupHeartbeat Request (Version: 0-1) => group_id member_id member_epoch instance_id rack_id rebalance_timeout_ms [subscribed_topic_names] subscribed_topic_regex server_assignor [topic_partitions] _tagged_fields

	group_id => COMPACT_STRING
	member_id => COMPACT_STRING
	member_epoch => INT32
	instance_id => COMPACT_NULLABLE_STRING
	rack_id => COMPACT_NULLABLE_STRING
	rebalance_timeout_ms => INT32
	subscribed_topic_names => COMPACT_NULLABLE_ARRAY of COMPACT_STRING (null when unchanged)
	subscribed_topic_regex => COMPACT_NULLABLE_STRING (1+)
	server_assignor => COMPACT_NULLABLE_STRING
	topic_partitions => topic_id [partitions] _tagged_fields (null when unchanged)
	  topic_id => UUID
	  partitions => INT32
*/
func parseConsumerGroupHeartbeat(r *largebuf.LargeBufferReader, header KafkaRequestHeader) (*GroupRequest, error) {
	groupID, err := readGroupID(r, header)
	if err != nil {
		return nil, err
	}
	req := &GroupRequest{GroupID: groupID}

	if req.MemberID, err = readPrintableString(r, header); err != nil {
		return req, nil
	}
	if req.MemberEpoch, err = readInt32(r); err != nil { // member_epoch: 0 join, >0 member, <0 leave
		return req, nil
	}
	if err = skipString(r, header); err != nil { // instance_id
		return req, nil
	}
	if err = skipString(r, header); err != nil { // rack_id
		return req, nil
	}
	if err = r.Skip(Int32Len); err != nil { // rebalance_timeout_ms
		return req, nil
	}
	namesLen, namesNull, err := readCompactNullableArrayLength(r)
	if err != nil {
		return req, nil
	}
	for range min(namesLen, maxGroupTopics) {
		name, err := readString(r, header, false)
		if err != nil {
			return req, nil
		}
		req.Topics = append(req.Topics, &GroupTopic{Name: name})
	}
	// A non-null list is the member's whole subscription, null means unchanged. Empty
	// is a real subscription: a member subscribed by regex joins with an empty list.
	// The owned partitions appended below are consumed topics, so they belong to it too.
	req.Subscription = !namesNull && namesLen <= maxGroupTopics
	if header.APIVersion() >= 1 {
		if err = skipString(r, header); err != nil { // subscribed_topic_regex
			return req, nil
		}
	}
	if err = skipString(r, header); err != nil { // server_assignor
		return req, nil
	}
	req.Topics = append(req.Topics, parseGroupTopics(r, header, true, skipInt32)...)
	return req, nil
}

// parseGroupTopics walks a topics array whose entries are
// (name | topic_id) [partitions] _tagged_fields, keeping the reader aligned by
// skipping every partition entry with skipPartition. Errors end the walk and the
// topics read so far are returned: a truncated buffer is the normal case.
func parseGroupTopics(r *largebuf.LargeBufferReader, header KafkaRequestHeader, byUUID bool,
	skipPartition func(*largebuf.LargeBufferReader, KafkaRequestHeader) error,
) []*GroupTopic {
	topicsLen, err := readArrayLength(r, header)
	if err != nil {
		return nil
	}
	var topics []*GroupTopic
	for range min(topicsLen, maxGroupTopics) {
		var topic GroupTopic
		if byUUID {
			topic.UUID, err = readUUID(r)
		} else {
			topic.Name, err = readString(r, header, false)
		}
		if err != nil {
			return topics
		}
		topics = append(topics, &topic)

		partitionsLen, err := readArrayLength(r, header)
		if err != nil {
			return topics
		}
		for range min(partitionsLen, maxGroupPartitions) {
			if err = skipPartition(r, header); err != nil {
				return topics
			}
		}
		if err = skipTaggedFields(r, header); err != nil {
			return topics
		}
	}
	return topics
}

func skipInt32(r *largebuf.LargeBufferReader, _ KafkaRequestHeader) error {
	return r.Skip(Int32Len)
}

// readGroupID reads a non-empty group id.
func readGroupID(r *largebuf.LargeBufferReader, header KafkaRequestHeader) (string, error) {
	groupID, err := readPrintableString(r, header)
	if err != nil {
		return "", err
	}
	if groupID == "" {
		return "", errKafkaInvalidGroupID
	}
	return groupID, nil
}

// readPrintableString reads a string field Kafka does not restrict to the topic-name
// charset (group ids, member ids, protocol types): printable UTF-8 is all that is
// required. A null or empty value yields "" whatever the field's nullability: a first
// JoinGroup carries an empty member_id, and the callers decide what "" means.
func readPrintableString(r *largebuf.LargeBufferReader, header KafkaRequestHeader) (string, error) {
	size, err := readStringSize(r, header)
	if err != nil {
		return "", err
	}
	if size == 0 {
		return "", nil
	}
	if r.Remaining() < size {
		return "", errKafkaStringSizeExceedsPacket
	}
	b, err := r.ReadN(size)
	if err != nil {
		return "", errKafkaStringSizeExceedsPacket
	}
	if !utf8.Valid(b) {
		return "", errKafkaInvalidPrintableString
	}
	for _, c := range b {
		if c < ' ' || c == 0x7f {
			return "", errKafkaInvalidPrintableString
		}
	}
	return string(b), nil
}

// readValidatedString reads size bytes and applies the topic-name character rules.
func readValidatedString(r *largebuf.LargeBufferReader, size int) (string, error) {
	if r.Remaining() < size {
		return "", errKafkaStringSizeExceedsPacket
	}
	b, err := r.ReadN(size)
	if err != nil {
		return "", errKafkaStringSizeExceedsPacket
	}
	if !validateKafkaString(b, size) {
		return "", errKafkaInvalidCharactersInString
	}
	return string(b), nil
}

// skipString advances past a string field of any nullability, empty or null.
func skipString(r *largebuf.LargeBufferReader, header KafkaRequestHeader) error {
	size, err := readStringSize(r, header)
	if err != nil {
		return err
	}
	return r.Skip(size)
}

// readStringSize reads the length prefix of a string field of any nullability; null and
// empty both yield 0 (readStringLength rejects an empty non-nullable string).
func readStringSize(r *largebuf.LargeBufferReader, header KafkaRequestHeader) (int, error) {
	var size int
	var err error
	if isFlexible(header) {
		size, err = readCompactLength(r)
	} else {
		size, err = readInt16(r)
	}
	if err != nil {
		return 0, err
	}
	return max(size, 0), nil
}

// readBytesLength reads the length prefix of a BYTES / COMPACT_BYTES field;
// null (-1 or compact 0) yields 0.
func readBytesLength(r *largebuf.LargeBufferReader, header KafkaRequestHeader) (int, error) {
	if isFlexible(header) {
		return readCompactLength(r)
	}
	b, err := r.ReadN(Int32Len)
	if err != nil {
		return 0, errKafkaDataTooShortForInt32
	}
	return max(int(int32(binary.BigEndian.Uint32(b))), 0), nil
}

// readCompactLength decodes a compact length prefix (uvarint of length + 1);
// null (0) yields 0.
func readCompactLength(r *largebuf.LargeBufferReader) (int, error) {
	size, _, err := readCompactNullableArrayLength(r)
	return size, err
}

// readCompactNullableArrayLength decodes a COMPACT_NULLABLE_ARRAY length prefix,
// telling a null array (0) apart from an empty one (1).
func readCompactNullableArrayLength(r *largebuf.LargeBufferReader) (length int, null bool, err error) {
	size, err := readUnsignedVarint(r)
	if err != nil {
		return 0, false, err
	}
	if size == 0 {
		return 0, true, nil
	}
	return size - 1, false, nil
}

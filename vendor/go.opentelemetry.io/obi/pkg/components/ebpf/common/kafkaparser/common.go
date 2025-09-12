// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kafkaparser

import (
	"encoding/binary"
	"errors"
)

const (
	Int8Len            = 1
	Int16Len           = 2
	Int32Len           = 4
	Int64Len           = 8
	UUIDLen            = 16
	MinKafkaRequestLen = // 14
	Int32Len +         // MessageSize
		Int16Len + // APIKey
		Int16Len + // APIVersion
		Int32Len + // CorrelationID
		Int16Len // Length of ClientID
	MinKafkaResponseLen = Int32Len + // MessageSize
		Int32Len // CorrelationID
	KafkaMaxPayloadLen = 20 * 1024 * 1024 // 20 MB max, 1MB is default for most Kafka installations
)

type KafkaAPIKey int8

const (
	APIKeyProduce  KafkaAPIKey = 0
	APIKeyFetch    KafkaAPIKey = 1
	APIKeyMetadata KafkaAPIKey = 3
)

type (
	UUID   [UUIDLen]byte
	Offset = int
)

type KafkaRequestHeader struct {
	MessageSize   int32
	APIKey        KafkaAPIKey
	APIVersion    int16
	CorrelationID int32
	ClientID      string
}

type KafkaResponseHeader struct {
	MessageSize   int32
	CorrelationID int32
}

func ParseKafkaRequestHeader(pkt []byte) (*KafkaRequestHeader, Offset, error) {
	if len(pkt) < MinKafkaRequestLen {
		return nil, 0, errors.New("packet too short for Kafka request header")
	}
	header := &KafkaRequestHeader{
		MessageSize:   int32(binary.BigEndian.Uint32(pkt[0:4])),
		APIKey:        KafkaAPIKey(int16(binary.BigEndian.Uint16(pkt[4:6]))),
		APIVersion:    int16(binary.BigEndian.Uint16(pkt[6:8])),
		CorrelationID: int32(binary.BigEndian.Uint32(pkt[8:12])),
	}

	clientIDSize := int16(binary.BigEndian.Uint16(pkt[12:14]))
	err := validateKafkaRequestHeader(header)
	if err != nil {
		return nil, 0, err
	}
	if clientIDSize < 0 {
		return nil, 0, errors.New("invalid client ID size")
	}
	offset := MinKafkaRequestLen
	if clientIDSize == 0 {
		header.ClientID = ""
		return header, offset, nil
	}
	if offset+int(clientIDSize) > len(pkt) {
		return nil, 0, errors.New("packet too short for client ID")
	}
	header.ClientID = string(pkt[offset : offset+int(clientIDSize)])
	offset += int(clientIDSize)
	offset, err = skipTaggedFields(pkt, header, offset)
	if err != nil {
		return nil, 0, err
	}
	return header, offset, nil
}

func ParseKafkaResponseHeader(pkt []byte, requestHeader *KafkaRequestHeader) (*KafkaResponseHeader, Offset, error) {
	if len(pkt) < MinKafkaResponseLen {
		return nil, 0, errors.New("packet too short for Kafka response header")
	}
	header := &KafkaResponseHeader{
		MessageSize:   int32(binary.BigEndian.Uint32(pkt[0:4])),
		CorrelationID: int32(binary.BigEndian.Uint32(pkt[4:8])),
	}

	offset := MinKafkaResponseLen
	err := validateKafkaResponseHeader(header, requestHeader)
	if err != nil {
		return nil, 0, err
	}
	offset, err = skipTaggedFields(pkt, requestHeader, offset)
	if err != nil {
		return nil, 0, err
	}
	return header, offset, nil
}

func skipTaggedFields(pkt []byte, header *KafkaRequestHeader, offset Offset) (Offset, error) {
	if !isFlexible(header) {
		return offset, nil // no tagged fields to skip for non-flexible versions
	}
	taggedFieldsLen, offset, err := readUnsignedVarint(pkt[offset:], offset)
	if err != nil {
		return 0, err
	}

	for i := 0; i < taggedFieldsLen; i++ {
		_, offset, err = readUnsignedVarint(pkt[offset:], offset) // read tag ID
		if err != nil {
			return 0, err
		}
		var tagLen int
		tagLen, offset, err = readUnsignedVarint(pkt[offset:], offset) // read tag length
		if err != nil {
			return 0, err
		}
		offset, err = skipBytes(pkt, offset, tagLen) // skip tag value
		if err != nil {
			return 0, err
		}
	}
	return offset, nil
}

func validateKafkaRequestHeader(header *KafkaRequestHeader) error {
	if header.MessageSize < int32(MinKafkaRequestLen) || header.APIVersion < 0 {
		return errors.New("invalid Kafka request header: size or version is negative")
	}

	if header.MessageSize > KafkaMaxPayloadLen {
		return errors.New("invalid Kafka request header: message size exceeds maximum payload length")
	}

	switch header.APIKey {
	case APIKeyFetch:
		if header.APIVersion > 18 { // latest: Fetch Request (Version: 17)
			return errors.New("invalid Kafka request header: unsupported API key version for Fetch")
		}
	case APIKeyProduce:
		if header.APIVersion > 13 { // latest: Produce Request (Version: 12)
			return errors.New("invalid Kafka request header: unsupported API key version for Produce")
		}
	case APIKeyMetadata:
		if header.APIVersion < 10 || header.APIVersion > 13 { // latest: Metadata Request (Version: 13), only versions 10-13 contain topic_id which we are interested in
			return errors.New("invalid Kafka request header: unsupported API key version for Metadata")
		}
	default:
		return errors.New("invalid Kafka request header: unsupported API key")
	}
	if header.CorrelationID < 0 {
		return errors.New("invalid Kafka request header: correlation ID is negative")
	}
	return nil
}

func validateKafkaResponseHeader(header *KafkaResponseHeader, requestHeader *KafkaRequestHeader) error {
	if header.MessageSize < MinKafkaResponseLen {
		return errors.New("invalid Kafka response header: size too small")
	}

	if header.MessageSize > KafkaMaxPayloadLen {
		return errors.New("invalid Kafka response header: message size exceeds maximum payload length")
	}

	if header.CorrelationID < 0 {
		return errors.New("invalid Kafka response header: correlation ID is negative")
	}
	if header.CorrelationID != requestHeader.CorrelationID {
		return errors.New("invalid Kafka response header: correlation ID does not match request header")
	}
	return nil
}

// isFlexible checks for each API key if the version is flexible.
// a flexible version uses a dynamic size for arrays and strings
func isFlexible(header *KafkaRequestHeader) bool {
	switch header.APIKey {
	// https://github.com/apache/kafka/blob/9983331d917fe8f57c37c88f0749b757e5af0c87/clients/src/main/resources/common/message/ProduceRequest.json#L51
	case APIKeyProduce:
		return header.APIVersion >= 9
	// https://github.com/apache/kafka/blob/9983331d917fe8f57c37c88f0749b757e5af0c87/clients/src/main/resources/common/message/FetchRequest.json#L62C4-L62C20
	case APIKeyFetch:
		return header.APIVersion >= 12
	// https://github.com/apache/kafka/blob/9983331d917fe8f57c37c88f0749b757e5af0c87/clients/src/main/resources/common/message/MetadataRequest.json#L22
	case APIKeyMetadata:
		return header.APIVersion >= 9
	default:
		return false
	}
}

func readArrayLength(pkt []byte, header *KafkaRequestHeader, offset Offset) (int, Offset, error) {
	if isFlexible(header) {
		size, offset, err := readUnsignedVarint(pkt[offset:], offset)
		if size == 0 {
			return 0, offset, nil // return 0 for null
		}
		return size - 1, offset, err
	} else {
		return readInt32(pkt, offset)
	}
}

func readUUID(pkt []byte, offset Offset) (*UUID, Offset, error) {
	if offset+UUIDLen > len(pkt) {
		return nil, offset, errors.New("packet too short for topic UUID")
	}
	uuid := (UUID)(pkt[offset : offset+UUIDLen])
	return &uuid, offset + UUIDLen, nil
}

func readString(pkt []byte, header *KafkaRequestHeader, offset Offset, nullable bool) (string, Offset, error) {
	size, offset, err := readStringLength(pkt, header, offset, nullable)
	if err != nil {
		return "", offset, err
	}
	if nullable && size == 0 {
		return "", offset, nil // return empty string for null
	}
	if offset+size > len(pkt) {
		return "", 0, errors.New("string size exceeds packet size")
	}
	if !validateKafkaString(pkt[offset:offset+size], size) {
		return "", 0, errors.New("invalid characters in string")
	}
	str := string(pkt[offset : offset+size])
	return str, offset + size, nil
}

func validateKafkaString(pkt []byte, size int) bool {
	for j := 0; j < size; j++ {
		ch := pkt[j]
		if ('a' <= ch && ch <= 'z') || ('A' <= ch && ch <= 'Z') || ('0' <= ch && ch <= '9') || ch == '.' || ch == '_' || ch == '-' {
			continue
		}
		return false
	}
	return true
}

func readStringLength(pkt []byte, header *KafkaRequestHeader, offset Offset, nullable bool) (int, Offset, error) {
	if !isFlexible(header) {
		// length is stored as a fixed size int16
		if offset+Int16Len > len(pkt) {
			return 0, 0, errors.New("packet too short for string length")
		}
		size := int16(binary.BigEndian.Uint16(pkt[offset:]))
		if nullable && size == -1 {
			return 0, offset + Int16Len, nil // return 0 for null
		}
		return int(size), offset + Int16Len, nil
	}

	// length is stored as a varint
	size, offset, err := readUnsignedVarint(pkt[offset:], offset)
	if err != nil {
		return 0, 0, err
	}
	if nullable && size == 0 {
		return 0, offset, nil // return 0 for null
	}
	if size <= 0 {
		return 0, 0, errors.New("invalid string size")
	}
	size-- // size is stored as a varint, so we subtract 1
	return size, offset, nil
}

func readUnsignedVarint(data []byte, offset Offset) (int, Offset, error) {
	value := 0
	i := 0
	for idx := 0; idx < len(data); idx++ {
		if idx > len(data) {
			return 0, 0, errors.New("offset exceeds data length")
		}
		b := data[idx]
		if (b & 0x80) == 0 {
			value |= int(b) << i
			return value, offset + idx + 1, nil
		}
		value |= int(b&0x7F) << i
		i += 7
		if i > 28 {
			return 0, 0, errors.New("illegal varint")
		}
	}
	return 0, 0, errors.New("data ended before varint was complete")
}

func skipBytes(pkt []byte, offset Offset, length int) (Offset, error) {
	if offset+length > len(pkt) {
		return 0, errors.New("offset and length exceed packet size")
	}
	return offset + length, nil
}

func readInt32(data []byte, offset Offset) (int, Offset, error) {
	if offset+Int32Len > len(data) {
		return 0, 0, errors.New("data too short for uint32")
	}
	value := int(binary.BigEndian.Uint32(data[offset:]))
	return value, offset + Int32Len, nil
}

func readInt64(data []byte, offset Offset) (int64, Offset, error) {
	if offset+Int64Len > len(data) {
		return 0, 0, errors.New("data too short for uint32")
	}
	value := int64(binary.BigEndian.Uint64(data[offset:]))
	return value, offset + Int64Len, nil
}

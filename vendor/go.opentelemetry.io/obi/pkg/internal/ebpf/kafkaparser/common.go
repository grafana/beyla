// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kafkaparser // import "go.opentelemetry.io/obi/pkg/internal/ebpf/kafkaparser"

import (
	"encoding/binary"
	"errors"

	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

// Protocol details
// https://kafka.apache.org/41/design/protocol/

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

type UUID [UUIDLen]byte

// KafkaRequestHeader is a zero-copy view over a *largebuf.LargeBuffer.
// Fixed-width fields are read on demand via scalar accessors; ClientID is
// read on demand from offset 14 using the stored length.
type KafkaRequestHeader struct {
	lb          *largebuf.LargeBuffer
	bodyOffset  int32 // absolute offset of the first request-body byte
	clientIDLen int16 // ≥ 0 guaranteed after successful construction
}

func (h KafkaRequestHeader) MessageSize() int32 {
	v, _ := h.lb.I32BEAt(0)
	return v
}

func (h KafkaRequestHeader) APIKey() KafkaAPIKey {
	v, _ := h.lb.I16BEAt(4)
	return KafkaAPIKey(v)
}

func (h KafkaRequestHeader) APIVersion() int16 {
	v, _ := h.lb.I16BEAt(6)
	return v
}

func (h KafkaRequestHeader) CorrelationID() int32 {
	v, _ := h.lb.I32BEAt(8)
	return v
}

// ClientID reads the client ID on demand from the underlying buffer.
// The Kafka wire format stores the length as an INT16 at offset 12,
// followed by N UTF-8 bytes starting at offset 14.
func (h KafkaRequestHeader) ClientID() string {
	if h.clientIDLen == 0 {
		return ""
	}
	b, _ := h.lb.UnsafeViewAt(14, int(h.clientIDLen))
	return string(b)
}

func (h KafkaRequestHeader) NewBodyReader() (largebuf.LargeBufferReader, error) {
	r := h.lb.NewReader()

	err := r.Skip(int(h.bodyOffset))
	if err != nil {
		return largebuf.LargeBufferReader{}, err
	}

	return r, nil
}

func NewKafkaRequestHeader(lb *largebuf.LargeBuffer) (KafkaRequestHeader, error) {
	if lb.Len() < MinKafkaRequestLen {
		return KafkaRequestHeader{}, errors.New("packet too short for Kafka request header")
	}

	h := KafkaRequestHeader{lb: lb}

	if err := h.validate(); err != nil {
		return KafkaRequestHeader{}, err
	}

	// ClientID: length at offset 12 (INT16), data at offset 14.
	clientIDLen, err := lb.I16BEAt(12)
	if err != nil {
		return KafkaRequestHeader{}, err
	}

	if clientIDLen < 0 {
		return KafkaRequestHeader{}, errors.New("invalid client ID size")
	}

	clientIDEnd := 14 + int(clientIDLen)
	if lb.Len() < clientIDEnd {
		return KafkaRequestHeader{}, errors.New("packet too short for client ID")
	}

	h.clientIDLen = clientIDLen

	bodyOff := clientIDEnd
	if isFlexible(h) {
		bodyOff, err = skipTaggedFieldsAt(lb, clientIDEnd)
		if err != nil {
			return KafkaRequestHeader{}, err
		}
	}
	h.bodyOffset = int32(bodyOff)
	return h, nil
}

type KafkaResponseHeader struct {
	MessageSize   int32
	CorrelationID int32
}

func ParseKafkaResponseHeader(r *largebuf.LargeBufferReader, requestHeader KafkaRequestHeader) (*KafkaResponseHeader, error) {
	if r.Remaining() < MinKafkaResponseLen {
		return nil, errors.New("packet too short for Kafka response header")
	}
	msgSizeBytes, err := r.ReadN(Int32Len)
	if err != nil {
		return nil, err
	}
	correlationIDBytes, err := r.ReadN(Int32Len)
	if err != nil {
		return nil, err
	}
	header := &KafkaResponseHeader{
		MessageSize:   int32(binary.BigEndian.Uint32(msgSizeBytes)),
		CorrelationID: int32(binary.BigEndian.Uint32(correlationIDBytes)),
	}

	if err := validateKafkaResponseHeader(header, requestHeader); err != nil {
		return nil, err
	}
	if err := skipTaggedFields(r, requestHeader); err != nil {
		return nil, err
	}
	return header, nil
}

func skipTaggedFields(r *largebuf.LargeBufferReader, header KafkaRequestHeader) error {
	if !isFlexible(header) {
		return nil // no tagged fields to skip for non-flexible versions
	}
	taggedFieldsLen, err := readUnsignedVarint(r)
	if err != nil {
		return err
	}
	for range taggedFieldsLen {
		if _, err = readUnsignedVarint(r); err != nil { // read tag ID
			return err
		}
		tagLen, err := readUnsignedVarint(r) // read tag length
		if err != nil {
			return err
		}
		if err = r.Skip(tagLen); err != nil { // skip tag value
			return err
		}
	}
	return nil
}

// skipTaggedFieldsAt skips flexible-version tagged fields starting at absolute
// offset off in lb, returning the new absolute offset after all tagged fields.
func skipTaggedFieldsAt(lb *largebuf.LargeBuffer, off int) (int, error) {
	count, n, err := readUVarintAt(lb, off)
	if err != nil {
		return 0, err
	}
	off += n
	for range count {
		_, n, err = readUVarintAt(lb, off) // tag ID
		if err != nil {
			return 0, err
		}
		off += n
		tagLen, n, err := readUVarintAt(lb, off) // tag length
		if err != nil {
			return 0, err
		}
		if tagLen < 0 || tagLen > lb.Len()-off-n {
			return 0, errors.New("tagged field value exceeds buffer")
		}
		off += n + tagLen
	}
	return off, nil
}

// readUVarintAt reads an unsigned varint from lb at absolute offset off.
// Returns value, bytes consumed, and any error.
func readUVarintAt(lb *largebuf.LargeBuffer, off int) (int, int, error) {
	value, shift, n := 0, 0, 0
	for {
		b, err := lb.U8At(off + n)
		if err != nil {
			return 0, 0, errors.New("data ended before varint was complete")
		}
		n++
		if b&0x80 == 0 {
			value |= int(b) << shift
			return value, n, nil
		}
		value |= int(b&0x7F) << shift
		shift += 7
		if shift > 28 {
			return 0, 0, errors.New("illegal varint")
		}
	}
}

func (h KafkaRequestHeader) validate() error {
	if h.MessageSize() < int32(MinKafkaRequestLen) {
		return errors.New("invalid Kafka request header: message size too small")
	}

	if h.APIVersion() < 0 {
		return errors.New("invalid Kafka request header: API version is negative")
	}

	if h.MessageSize() > KafkaMaxPayloadLen {
		return errors.New("invalid Kafka request header: message size exceeds maximum payload length")
	}

	switch h.APIKey() {
	case APIKeyFetch:
		if h.APIVersion() > 18 { // latest: Fetch Request (Version: 17)
			return errors.New("invalid Kafka request header: unsupported API key version for Fetch")
		}
	case APIKeyProduce:
		if h.APIVersion() > 13 { // latest: Produce Request (Version: 13)
			return errors.New("invalid Kafka request header: unsupported API key version for Produce")
		}
	case APIKeyMetadata:
		if h.APIVersion() < 10 || h.APIVersion() > 13 { // latest: Metadata Request (Version: 13), only versions 10-13 contain topic_id which we are interested in
			return errors.New("invalid Kafka request header: unsupported API key version for Metadata")
		}
	default:
		return errors.New("invalid Kafka request header: unsupported API key")
	}
	if h.CorrelationID() < 0 {
		return errors.New("invalid Kafka request header: correlation ID is negative")
	}
	return nil
}

func validateKafkaResponseHeader(header *KafkaResponseHeader, requestHeader KafkaRequestHeader) error {
	if header.MessageSize < MinKafkaResponseLen {
		return errors.New("invalid Kafka response header: size too small")
	}

	if header.MessageSize > KafkaMaxPayloadLen {
		return errors.New("invalid Kafka response header: message size exceeds maximum payload length")
	}

	if header.CorrelationID < 0 {
		return errors.New("invalid Kafka response header: correlation ID is negative")
	}
	if header.CorrelationID != requestHeader.CorrelationID() {
		return errors.New("invalid Kafka response header: correlation ID does not match request header")
	}
	return nil
}

// isFlexible checks for each API key if the version is flexible.
// a flexible version uses a dynamic size for arrays and strings
func isFlexible(header KafkaRequestHeader) bool {
	ver := header.APIVersion()
	switch header.APIKey() {
	// https://github.com/apache/kafka/blob/9983331d917fe8f57c37c88f0749b757e5af0c87/clients/src/main/resources/common/message/ProduceRequest.json#L51
	case APIKeyProduce:
		return ver >= 9
	// https://github.com/apache/kafka/blob/9983331d917fe8f57c37c88f0749b757e5af0c87/clients/src/main/resources/common/message/FetchRequest.json#L62C4-L62C20
	case APIKeyFetch:
		return ver >= 12
	// https://github.com/apache/kafka/blob/9983331d917fe8f57c37c88f0749b757e5af0c87/clients/src/main/resources/common/message/MetadataRequest.json#L22
	case APIKeyMetadata:
		return ver >= 9
	default:
		return false
	}
}

func readArrayLength(r *largebuf.LargeBufferReader, header KafkaRequestHeader) (int, error) {
	if isFlexible(header) {
		size, err := readUnsignedVarint(r)
		if err != nil {
			return 0, err
		}
		if size == 0 {
			return 0, nil // return 0 for null
		}
		return size - 1, nil
	}
	return readInt32(r)
}

func readUUID(r *largebuf.LargeBufferReader) (*UUID, error) {
	b, err := r.ReadN(UUIDLen)
	if err != nil {
		return nil, errors.New("packet too short for topic UUID")
	}
	var uuid UUID
	copy(uuid[:], b)
	return &uuid, nil
}

func readString(r *largebuf.LargeBufferReader, header KafkaRequestHeader, nullable bool) (string, error) {
	size, err := readStringLength(r, header, nullable)
	if err != nil {
		return "", err
	}
	if nullable && size == 0 {
		return "", nil // return empty string for null
	}
	if r.Remaining() < size {
		return "", errors.New("string size exceeds packet size")
	}
	b, err := r.ReadN(size)
	if err != nil {
		return "", errors.New("string size exceeds packet size")
	}
	if !validateKafkaString(b, size) {
		return "", errors.New("invalid characters in string")
	}
	return string(b), nil
}

func validateKafkaString(pkt []byte, size int) bool {
	for j := range size {
		ch := pkt[j]
		if ('a' <= ch && ch <= 'z') || ('A' <= ch && ch <= 'Z') || ('0' <= ch && ch <= '9') || ch == '.' || ch == '_' || ch == '-' {
			continue
		}
		return false
	}
	return true
}

func readStringLength(r *largebuf.LargeBufferReader, header KafkaRequestHeader, nullable bool) (int, error) {
	if !isFlexible(header) {
		// length is stored as a fixed size int16
		if r.Remaining() < Int16Len {
			return 0, errors.New("packet too short for string length")
		}
		b, err := r.ReadN(Int16Len)
		if err != nil {
			return 0, errors.New("packet too short for string length")
		}
		size := int16(binary.BigEndian.Uint16(b))
		if nullable && size == -1 {
			return 0, nil // return 0 for null
		}
		if size < 1 {
			return 0, errors.New("invalid string size")
		}
		return int(size), nil
	}

	// length is stored as a varint
	size, err := readUnsignedVarint(r)
	if err != nil {
		return 0, err
	}
	if nullable && size == 0 {
		return 0, nil // return 0 for null
	}
	if size <= 0 {
		return 0, errors.New("invalid string size")
	}
	size-- // size is stored as a varint, so we subtract 1
	if size < 0 {
		return 0, errors.New("invalid string size")
	}
	return size, nil
}

func readUnsignedVarint(r *largebuf.LargeBufferReader) (int, error) {
	value := 0
	i := 0
	for {
		if r.Remaining() == 0 {
			return 0, errors.New("data ended before varint was complete")
		}
		b, err := r.ReadN(1)
		if err != nil {
			return 0, err
		}
		if (b[0] & 0x80) == 0 {
			value |= int(b[0]) << i
			return value, nil
		}
		value |= int(b[0]&0x7F) << i
		i += 7
		if i > 28 {
			return 0, errors.New("illegal varint")
		}
	}
}

func readInt32(r *largebuf.LargeBufferReader) (int, error) {
	b, err := r.ReadN(Int32Len)
	if err != nil {
		return 0, errors.New("data too short for int32")
	}
	return int(binary.BigEndian.Uint32(b)), nil
}

func readInt64(r *largebuf.LargeBufferReader) (int64, error) {
	b, err := r.ReadN(Int64Len)
	if err != nil {
		return 0, errors.New("data too short for int64")
	}
	return int64(binary.BigEndian.Uint64(b)), nil
}

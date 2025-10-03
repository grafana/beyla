// Copyright 2020 VMware, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package entities

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
)

type IEDataType uint8

const (
	OctetArray IEDataType = iota
	Unsigned8
	Unsigned16
	Unsigned32
	Unsigned64
	Signed8
	Signed16
	Signed32
	Signed64
	Float32
	Float64
	Boolean
	MacAddress
	String
	DateTimeSeconds
	DateTimeMilliseconds
	DateTimeMicroseconds
	DateTimeNanoseconds
	Ipv4Address
	Ipv6Address
	BasicList
	SubTemplateList
	SubTemplateMultiList
	InvalidDataType = 255
)

const VariableLength uint16 = 65535

var InfoElementLength = map[IEDataType]uint16{
	OctetArray:           VariableLength,
	Unsigned8:            1,
	Unsigned16:           2,
	Unsigned32:           4,
	Unsigned64:           8,
	Signed8:              1,
	Signed16:             2,
	Signed32:             4,
	Signed64:             8,
	Float32:              4,
	Float64:              8,
	Boolean:              1,
	MacAddress:           6,
	String:               VariableLength,
	DateTimeSeconds:      4,
	DateTimeMilliseconds: 8,
	DateTimeMicroseconds: 8,
	DateTimeNanoseconds:  8,
	Ipv4Address:          4,
	Ipv6Address:          16,
	BasicList:            VariableLength,
	SubTemplateList:      VariableLength,
	SubTemplateMultiList: VariableLength,
	InvalidDataType:      0,
}

// InfoElement (IE) follows the specification in Section 2.1 of RFC7012
type InfoElement struct {
	// Name of the IE
	Name string
	// Identifier for IE; follows Section 4.3 of RFC7013
	ElementId uint16
	// dataType follows the specification in RFC7012(section 3.1)/RFC5610(section 3.1)
	DataType IEDataType
	// Enterprise number or 0 (0 for IANA registry)
	EnterpriseId uint32
	// Length of IE
	Len uint16
}

func NewInfoElement(name string, ieID uint16, ieType IEDataType, entID uint32, len uint16) *InfoElement {
	return &InfoElement{
		Name:         name,
		ElementId:    ieID,
		DataType:     ieType,
		EnterpriseId: entID,
		Len:          len,
	}
}

func IENameToType(name string) IEDataType {
	switch name {
	case "octetArray":
		return OctetArray
	case "unsigned8":
		return Unsigned8
	case "unsigned16":
		return Unsigned16
	case "unsigned32":
		return Unsigned32
	case "unsigned64":
		return Unsigned64
	case "signed8":
		return Signed8
	case "signed16":
		return Signed16
	case "signed32":
		return Signed32
	case "signed64":
		return Signed64
	case "float32":
		return Float32
	case "float64":
		return Float64
	case "boolean":
		return Boolean
	case "macAddress":
		return MacAddress
	case "string":
		return String
	case "dateTimeSeconds":
		return DateTimeSeconds
	case "dateTimeMilliseconds":
		return DateTimeMilliseconds
	case "dateTimeMicroseconds":
		return DateTimeMicroseconds
	case "dateTimeNanoseconds":
		return DateTimeNanoseconds
	case "ipv4Address":
		return Ipv4Address
	case "ipv6Address":
		return Ipv6Address
	case "basicList":
		return BasicList
	case "subTemplateList":
		return SubTemplateList
	case "subTemplateMultiList":
		return SubTemplateMultiList
	}
	return InvalidDataType
}

// decodeToIEDataType is to decode to specific type. This is only used for testing.
func decodeToIEDataType(dataType IEDataType, val interface{}) (interface{}, error) {
	value, ok := val.([]byte)
	if !ok {
		return nil, fmt.Errorf("error when converting value to []bytes for decoding")
	}
	switch dataType {
	case OctetArray:
		return value, nil
	case Unsigned8:
		return value[0], nil
	case Unsigned16:
		return binary.BigEndian.Uint16(value), nil
	case Unsigned32:
		return binary.BigEndian.Uint32(value), nil
	case Unsigned64:
		return binary.BigEndian.Uint64(value), nil
	case Signed8:
		return int8(value[0]), nil
	case Signed16:
		return int16(binary.BigEndian.Uint16(value)), nil
	case Signed32:
		return int32(binary.BigEndian.Uint32(value)), nil
	case Signed64:
		return int64(binary.BigEndian.Uint64(value)), nil
	case Float32:
		return math.Float32frombits(binary.BigEndian.Uint32(value)), nil
	case Float64:
		return math.Float64frombits(binary.BigEndian.Uint64(value)), nil
	case Boolean:
		if int8(value[0]) == 1 {
			return true, nil
		} else {
			return false, nil
		}
	case DateTimeSeconds:
		v := binary.BigEndian.Uint32(value)
		return v, nil
	case DateTimeMilliseconds:
		v := binary.BigEndian.Uint64(value)
		return v, nil
	case DateTimeMicroseconds, DateTimeNanoseconds:
		return nil, fmt.Errorf("API does not support micro and nano seconds types yet")
	case MacAddress:
		return net.HardwareAddr(value), nil
	case Ipv4Address, Ipv6Address:
		return net.IP(value), nil
	case String:
		return string(value), nil
	default:
		return nil, fmt.Errorf("API supports only valid information elements with datatypes given in RFC7011")
	}
}

// DecodeAndCreateInfoElementWithValue takes in the info element and its value in bytes, and
// returns appropriate InfoElementWithValue.
func DecodeAndCreateInfoElementWithValue(element *InfoElement, value []byte) (InfoElementWithValue, error) {
	switch element.DataType {
	case OctetArray:
		var val []byte
		if value != nil {
			val = append(val, value...)
		}
		return NewOctetArrayInfoElement(element, val), nil
	case Unsigned8:
		var val uint8
		if value == nil {
			val = 0
		} else {
			val = value[0]
		}
		return NewUnsigned8InfoElement(element, val), nil
	case Unsigned16:
		var val uint16
		if value == nil {
			val = 0
		} else {
			val = binary.BigEndian.Uint16(value)
		}
		return NewUnsigned16InfoElement(element, val), nil
	case Unsigned32:
		var val uint32
		if value == nil {
			val = 0
		} else {
			val = binary.BigEndian.Uint32(value)
		}
		return NewUnsigned32InfoElement(element, val), nil
	case Unsigned64:
		var val uint64
		if value == nil {
			val = 0
		} else {
			val = binary.BigEndian.Uint64(value)
		}
		return NewUnsigned64InfoElement(element, val), nil
	case Signed8:
		var val int8
		if value == nil {
			val = 0
		} else {
			val = int8(value[0])
		}
		return NewSigned8InfoElement(element, val), nil
	case Signed16:
		var val int16
		if value == nil {
			val = 0
		} else {
			val = int16(binary.BigEndian.Uint16(value))
		}
		return NewSigned16InfoElement(element, val), nil
	case Signed32:
		var val int32
		if value == nil {
			val = 0
		} else {
			val = int32(binary.BigEndian.Uint32(value))
		}
		return NewSigned32InfoElement(element, val), nil
	case Signed64:
		var val int64
		if value == nil {
			val = 0
		}
		val = int64(binary.BigEndian.Uint64(value))
		return NewSigned64InfoElement(element, val), nil
	case Float32:
		var val float32
		if value == nil {
			val = 0
		} else {
			val = math.Float32frombits(binary.BigEndian.Uint32(value))
		}
		return NewFloat32InfoElement(element, val), nil
	case Float64:
		var val float64
		if value == nil {
			val = 0
		} else {
			val = math.Float64frombits(binary.BigEndian.Uint64(value))
		}
		return NewFloat64InfoElement(element, val), nil
	case Boolean:
		if value == nil {
			return NewBoolInfoElement(element, false), nil
		}
		if int8(value[0]) == 1 {
			return NewBoolInfoElement(element, true), nil
		} else {
			return NewBoolInfoElement(element, false), nil
		}
	case DateTimeSeconds:
		var val uint32
		if value == nil {
			val = 0
		} else {
			val = binary.BigEndian.Uint32(value)
		}
		return NewDateTimeSecondsInfoElement(element, val), nil
	case DateTimeMilliseconds:
		var val uint64
		if value == nil {
			val = 0
		} else {
			val = binary.BigEndian.Uint64(value)
		}
		return NewDateTimeMillisecondsInfoElement(element, val), nil
	case DateTimeMicroseconds, DateTimeNanoseconds:
		return nil, fmt.Errorf("API does not support micro and nano seconds types yet")
	case MacAddress:
		if value == nil {
			return NewMacAddressInfoElement(element, nil), nil
		} else {
			// make sure that we make a copy of the slice, instead of using it as is
			// otherwise the underlying array for value may not be GC'd until the IE is GC'd
			// the underlying array may be much larger than the value slice itself
			addr := append([]byte{}, value...)
			return NewMacAddressInfoElement(element, addr), nil
		}
	case Ipv4Address, Ipv6Address:
		if value == nil {
			return NewIPAddressInfoElement(element, nil), nil
		} else {
			// make sure that we make a copy of the slice, instead of using it as is
			// otherwise the underlying array for value may not be GC'd until the IE is GC'd
			// the underlying array may be much larger than the value slice itself
			addr := append([]byte{}, value...)
			return NewIPAddressInfoElement(element, addr), nil
		}
	case String:
		var val string
		if value == nil {
			val = ""
		} else {
			val = string(value)
		}
		return NewStringInfoElement(element, val), nil
	default:
		return nil, fmt.Errorf("API supports only valid information elements with datatypes given in RFC7011")
	}
}

// EncodeToIEDataType is to encode data to specific type to the buff. This is only
// used for testing.
func EncodeToIEDataType(dataType IEDataType, val interface{}) ([]byte, error) {
	switch dataType {
	case OctetArray:
		// Supporting the type properly would require knowing whether we are dealing with a
		// fixed-length or variable-length element.
		return nil, fmt.Errorf("octet array data type not supported by this method yet")
	case Unsigned8:
		v, ok := val.(uint8)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type uint8", val)
		}
		return []byte{v}, nil
	case Unsigned16:
		v, ok := val.(uint16)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type uint16", val)
		}
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, v)
		return b, nil
	case Unsigned32:
		v, ok := val.(uint32)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type uint32", val)
		}
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, v)
		return b, nil
	case Unsigned64:
		v, ok := val.(uint64)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type uint64", val)
		}
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, v)
		return b, nil
	case Signed8:
		v, ok := val.(int8)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type int8", val)
		}
		return []byte{byte(v)}, nil
	case Signed16:
		v, ok := val.(int16)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type int16", val)
		}
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(v))
		return b, nil
	case Signed32:
		v, ok := val.(int32)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type int32", val)
		}
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(v))
		return b, nil
	case Signed64:
		v, ok := val.(int64)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type int64", val)
		}
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(v))
		return b, nil
	case Float32:
		v, ok := val.(float32)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type float32", val)
		}
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, math.Float32bits(v))
		return b, nil
	case Float64:
		v, ok := val.(float64)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type float64", val)
		}
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, math.Float64bits(v))
		return b, nil
	case Boolean:
		v, ok := val.(bool)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type bool", val)
		}
		b := make([]byte, 1)
		// Following boolean spec from RFC7011
		if v {
			b[0] = byte(int8(1))
		} else {
			b[0] = byte(int8(2))
		}
		return b, nil
	case DateTimeSeconds:
		v, ok := val.(uint32)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type uint32", val)
		}
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, v)
		return b, nil
	case DateTimeMilliseconds:
		v, ok := val.(uint64)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type uint64", val)
		}
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, v)
		return b, nil
		// Currently only supporting seconds and milliseconds
	case DateTimeMicroseconds, DateTimeNanoseconds:
		// TODO: RFC 7011 has extra spec for these data types. Need to follow that
		return nil, fmt.Errorf("API does not support micro and nano seconds types yet")
	case MacAddress:
		// Expects net.Hardware type
		v, ok := val.(net.HardwareAddr)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type net.HardwareAddr for this element", val)
		}
		return v, nil
	case Ipv4Address:
		// Expects net.IP type
		v, ok := val.(net.IP)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type net.IP for this element", val)
		}
		if ipv4Addr := v.To4(); ipv4Addr != nil {
			return ipv4Addr, nil
		} else {
			return nil, fmt.Errorf("provided IP %v does not belong to IPv4 address family", v)
		}
	case Ipv6Address:
		// Expects net.IP type
		v, ok := val.(net.IP)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type net.IP for this element", val)
		}
		if ipv6Addr := v.To16(); ipv6Addr != nil {
			return ipv6Addr, nil
		} else {
			return nil, fmt.Errorf("provided IPv6 address %v is not of correct length", v)
		}
	case String:
		v, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type string for this element", val)
		}
		var encodedBytes []byte
		if len(v) < 255 {
			encodedBytes = make([]byte, len(v)+1)
			encodedBytes[0] = uint8(len(v))
			copy(encodedBytes[1:], v)
		} else if len(v) <= math.MaxUint16 {
			encodedBytes = make([]byte, len(v)+3)
			encodedBytes[0] = byte(255)
			binary.BigEndian.PutUint16(encodedBytes[1:3], uint16(len(v)))
			copy(encodedBytes[3:], v)
		} else {
			return nil, fmt.Errorf("provided String value is too long and cannot be encoded: len=%d, maxlen=%d", len(v), math.MaxUint16)
		}
		return encodedBytes, nil
	}
	return nil, fmt.Errorf("API supports only valid information elements with datatypes given in RFC7011")
}

// encodeInfoElementValueToBuff is to encode data to specific type to the buff
func encodeInfoElementValueToBuff(element InfoElementWithValue, buffer []byte, index int) error {
	if index+element.GetLength() > len(buffer) {
		return fmt.Errorf("buffer size is not enough for encoding")
	}
	switch element.GetDataType() {
	case OctetArray:
		v := element.GetOctetArrayValue()
		ieLen := element.GetInfoElement().Len
		if ieLen < VariableLength {
			// fixed length case
			if len(v) != int(ieLen) {
				return fmt.Errorf("invalid value for fixed-length octet array: length mismatch")
			}
			copy(buffer[index:], v)
		} else if len(v) < 255 {
			buffer[index] = uint8(len(v))
			copy(buffer[index+1:], v)
		} else if len(v) <= math.MaxUint16 {
			buffer[index] = byte(255) // marker byte for long array
			binary.BigEndian.PutUint16(buffer[index+1:index+3], uint16(len(v)))
			copy(buffer[index+3:], v)
		} else {
			return fmt.Errorf("provided OctetArray value is too long and cannot be encoded: len=%d, maxlen=%d", len(v), math.MaxUint16)
		}
	case Unsigned8:
		copy(buffer[index:index+1], []byte{element.GetUnsigned8Value()})
	case Unsigned16:
		binary.BigEndian.PutUint16(buffer[index:], element.GetUnsigned16Value())
	case Unsigned32:
		binary.BigEndian.PutUint32(buffer[index:], element.GetUnsigned32Value())
	case Unsigned64:
		binary.BigEndian.PutUint64(buffer[index:], element.GetUnsigned64Value())
	case Signed8:
		copy(buffer[index:index+1], []byte{byte(element.GetSigned8Value())})
	case Signed16:
		binary.BigEndian.PutUint16(buffer[index:], uint16(element.GetSigned16Value()))
	case Signed32:
		binary.BigEndian.PutUint32(buffer[index:], uint32(element.GetSigned32Value()))
	case Signed64:
		binary.BigEndian.PutUint64(buffer[index:], uint64(element.GetSigned64Value()))
	case Float32:
		binary.BigEndian.PutUint32(buffer[index:], math.Float32bits(element.GetFloat32Value()))
	case Float64:
		binary.BigEndian.PutUint64(buffer[index:], math.Float64bits(element.GetFloat64Value()))
	case Boolean:
		// Following boolean spec from RFC7011
		indicator := byte(int8(1))
		if !element.GetBooleanValue() {
			indicator = byte(int8(2))
		}
		copy(buffer[index:index+1], []byte{indicator})
	case DateTimeSeconds:
		binary.BigEndian.PutUint32(buffer[index:], element.GetUnsigned32Value())
	case DateTimeMilliseconds:
		binary.BigEndian.PutUint64(buffer[index:], element.GetUnsigned64Value())
		// Currently only supporting seconds and milliseconds
	case DateTimeMicroseconds, DateTimeNanoseconds:
		// TODO: RFC 7011 has extra spec for these data types. Need to follow that
		return fmt.Errorf("API does not support micro and nano seconds types yet")
	case MacAddress:
		copy(buffer[index:], element.GetMacAddressValue())
	case Ipv4Address:
		if ipv4Addr := element.GetIPAddressValue().To4(); ipv4Addr != nil {
			copy(buffer[index:], ipv4Addr)
		} else {
			return fmt.Errorf("provided IP %v does not belong to IPv4 address family", element.GetIPAddressValue())
		}
	case Ipv6Address:
		if ipv6Addr := element.GetIPAddressValue().To16(); ipv6Addr != nil {
			copy(buffer[index:], ipv6Addr)
		} else {
			return fmt.Errorf("provided IPv6 address %v is not of correct length", element.GetIPAddressValue())
		}
	case String:
		v := element.GetStringValue()
		if len(v) < 255 {
			buffer[index] = uint8(len(v))
			// See https://pkg.go.dev/builtin#copy
			// As a special case, it also will copy bytes from a string to a slice of bytes.
			copy(buffer[index+1:], v)
		} else if len(v) <= math.MaxUint16 {
			buffer[index] = byte(255) // marker byte for long strings
			binary.BigEndian.PutUint16(buffer[index+1:index+3], uint16(len(v)))
			copy(buffer[index+3:], v)
		} else {
			return fmt.Errorf("provided String value is too long and cannot be encoded: len=%d, maxlen=%d", len(v), math.MaxUint16)
		}
	default:
		return fmt.Errorf("API supports only valid information elements with datatypes given in RFC7011")
	}
	return nil
}

// appendInfoElementValueToBuffer appends the encoded element value to the provided buffer.
func appendInfoElementValueToBuffer(element InfoElementWithValue, buffer []byte) ([]byte, error) {
	switch element.GetDataType() {
	case OctetArray:
		v := element.GetOctetArrayValue()
		ieLen := element.GetInfoElement().Len
		if ieLen < VariableLength {
			// fixed length case
			if len(v) != int(ieLen) {
				return nil, fmt.Errorf("invalid value for fixed-length octet array: length mismatch")
			}
			buffer = append(buffer, v...)
		} else if len(v) < 255 {
			buffer = append(buffer, byte(len(v)))
			buffer = append(buffer, v...)
		} else if len(v) <= math.MaxUint16 {
			buffer = append(buffer, byte(255))
			buffer = binary.BigEndian.AppendUint16(buffer, uint16(len(v)))
			buffer = append(buffer, v...)
		} else {
			return nil, fmt.Errorf("provided OctetArray value is too long and cannot be encoded: len=%d, maxlen=%d", len(v), math.MaxUint16)
		}
	case Unsigned8:
		buffer = append(buffer, element.GetUnsigned8Value())
	case Unsigned16:
		buffer = binary.BigEndian.AppendUint16(buffer, element.GetUnsigned16Value())
	case Unsigned32:
		buffer = binary.BigEndian.AppendUint32(buffer, element.GetUnsigned32Value())
	case Unsigned64:
		buffer = binary.BigEndian.AppendUint64(buffer, element.GetUnsigned64Value())
	case Signed8:
		buffer = append(buffer, byte(element.GetSigned8Value()))
	case Signed16:
		buffer = binary.BigEndian.AppendUint16(buffer, uint16(element.GetSigned16Value()))
	case Signed32:
		buffer = binary.BigEndian.AppendUint32(buffer, uint32(element.GetSigned32Value()))
	case Signed64:
		buffer = binary.BigEndian.AppendUint64(buffer, uint64(element.GetSigned64Value()))
	case Float32:
		buffer = binary.BigEndian.AppendUint32(buffer, math.Float32bits(element.GetFloat32Value()))
	case Float64:
		buffer = binary.BigEndian.AppendUint64(buffer, math.Float64bits(element.GetFloat64Value()))
	case Boolean:
		// Following boolean spec from RFC7011
		indicator := byte(1)
		if !element.GetBooleanValue() {
			indicator = byte(2)
		}
		buffer = append(buffer, indicator)
	case DateTimeSeconds:
		buffer = binary.BigEndian.AppendUint32(buffer, element.GetUnsigned32Value())
	case DateTimeMilliseconds:
		buffer = binary.BigEndian.AppendUint64(buffer, element.GetUnsigned64Value())
		// Currently only supporting seconds and milliseconds
	case DateTimeMicroseconds, DateTimeNanoseconds:
		// TODO: RFC 7011 has extra spec for these data types. Need to follow that
		return nil, fmt.Errorf("API does not support micro and nano seconds types yet")
	case MacAddress:
		buffer = append(buffer, element.GetMacAddressValue()...)
	case Ipv4Address:
		if ipv4Add := element.GetIPAddressValue().To4(); ipv4Add != nil {
			buffer = append(buffer, ipv4Add...)
		} else {
			return nil, fmt.Errorf("provided IP %v does not belong to IPv4 address family", element.GetIPAddressValue())
		}
	case Ipv6Address:
		if ipv6Add := element.GetIPAddressValue().To16(); ipv6Add != nil {
			buffer = append(buffer, ipv6Add...)
		} else {
			return nil, fmt.Errorf("provided IPv6 address %v is not of correct length", element.GetIPAddressValue())
		}
	case String:
		v := element.GetStringValue()
		if len(v) < 255 {
			buffer = append(buffer, byte(len(v)))
			// See https://pkg.go.dev/builtin#append
			// As a special case, it is legal to append a string to a byte slice
			buffer = append(buffer, v...)
		} else if len(v) <= math.MaxUint16 {
			buffer = append(buffer, byte(255)) // marker byte for long strings
			buffer = binary.BigEndian.AppendUint16(buffer, uint16(len(v)))
			buffer = append(buffer, v...)
		} else {
			return nil, fmt.Errorf("provided String value is too long and cannot be encoded: len=%d, maxlen=%d", len(v), math.MaxUint16)
		}
	default:
		return nil, fmt.Errorf("API supports only valid information elements with datatypes given in RFC7011")
	}
	return buffer, nil
}

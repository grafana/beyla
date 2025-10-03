package entities

import (
	"net"
)

type InfoElementWithValue interface {
	GetName() string
	GetDataType() IEDataType
	// GetInfoElement retrieves the info element. This is called after AddInfoElement.
	// TODO: Handle error to make it more robust if it is called prior to AddInfoElement.
	GetInfoElement() *InfoElement
	AddInfoElement(infoElement *InfoElement)
	GetOctetArrayValue() []byte
	GetUnsigned8Value() uint8
	GetUnsigned16Value() uint16
	GetUnsigned32Value() uint32
	GetUnsigned64Value() uint64
	GetSigned8Value() int8
	GetSigned16Value() int16
	GetSigned32Value() int32
	GetSigned64Value() int64
	GetFloat32Value() float32
	GetFloat64Value() float64
	GetBooleanValue() bool
	GetMacAddressValue() net.HardwareAddr
	GetStringValue() string
	GetIPAddressValue() net.IP
	SetOctetArrayValue(val []byte)
	SetUnsigned8Value(val uint8)
	SetUnsigned16Value(val uint16)
	SetUnsigned32Value(val uint32)
	SetUnsigned64Value(val uint64)
	SetSigned8Value(val int8)
	SetSigned16Value(val int16)
	SetSigned32Value(val int32)
	SetSigned64Value(val int64)
	SetFloat32Value(val float32)
	SetFloat64Value(val float64)
	SetBooleanValue(val bool)
	SetMacAddressValue(val net.HardwareAddr)
	SetStringValue(val string)
	SetIPAddressValue(val net.IP)
	IsValueEmpty() bool
	GetLength() int
	ResetValue()
}

type baseInfoElement struct {
	element *InfoElement
}

func (b *baseInfoElement) GetName() string {
	return b.element.Name
}

func (b *baseInfoElement) GetDataType() IEDataType {
	return b.element.DataType
}

func (b *baseInfoElement) GetInfoElement() *InfoElement {
	return b.element
}

func (b *baseInfoElement) AddInfoElement(infoElement *InfoElement) {
	b.element = infoElement
}

func (b *baseInfoElement) GetOctetArrayValue() []byte {
	panic("accessing value of wrong data type")
}

func (b *baseInfoElement) GetUnsigned8Value() uint8 {
	panic("accessing value of wrong data type")
}

func (b *baseInfoElement) GetUnsigned16Value() uint16 {
	panic("accessing value of wrong data type")
}

func (b *baseInfoElement) GetUnsigned32Value() uint32 {
	panic("accessing value of wrong data type")
}

func (b *baseInfoElement) GetUnsigned64Value() uint64 {
	panic("accessing value of wrong data type")
}

func (b *baseInfoElement) GetSigned8Value() int8 {
	panic("accessing value of wrong data type")
}

func (b *baseInfoElement) GetSigned16Value() int16 {
	panic("accessing value of wrong data type")
}

func (b *baseInfoElement) GetSigned32Value() int32 {
	panic("accessing value of wrong data type")
}

func (b *baseInfoElement) GetSigned64Value() int64 {
	panic("accessing value of wrong data type")
}

func (b *baseInfoElement) GetFloat32Value() float32 {
	panic("accessing value of wrong data type")
}

func (b *baseInfoElement) GetFloat64Value() float64 {
	panic("accessing value of wrong data type")
}

func (b *baseInfoElement) GetBooleanValue() bool {
	panic("accessing value of wrong data type")
}

func (b *baseInfoElement) GetMacAddressValue() net.HardwareAddr {
	panic("accessing value of wrong data type")
}

func (b *baseInfoElement) GetStringValue() string {
	panic("accessing value of wrong data type")
}

func (b *baseInfoElement) GetIPAddressValue() net.IP {
	panic("accessing value of wrong data type")
}

func (b *baseInfoElement) SetOctetArrayValue(val []byte) {
	panic("setting value with wrong data type")
}

func (b *baseInfoElement) SetUnsigned8Value(val uint8) {
	panic("setting value with wrong data type")
}

func (b *baseInfoElement) SetUnsigned16Value(val uint16) {
	panic("setting value with wrong data type")
}

func (b *baseInfoElement) SetUnsigned32Value(val uint32) {
	panic("setting value with wrong data type")
}

func (b *baseInfoElement) SetUnsigned64Value(val uint64) {
	panic("setting value with wrong data type")
}

func (b *baseInfoElement) SetSigned8Value(val int8) {
	panic("setting value with wrong data type")
}

func (b *baseInfoElement) SetSigned16Value(val int16) {
	panic("setting value with wrong data type")
}

func (b *baseInfoElement) SetSigned32Value(val int32) {
	panic("setting value with wrong data type")
}

func (b *baseInfoElement) SetSigned64Value(val int64) {
	panic("setting value with wrong data type")
}

func (b *baseInfoElement) SetFloat32Value(val float32) {
	panic("setting value with wrong data type")
}

func (b *baseInfoElement) SetFloat64Value(val float64) {
	panic("setting value with wrong data type")
}

func (b *baseInfoElement) SetBooleanValue(val bool) {
	panic("setting value with wrong data type")
}

func (b *baseInfoElement) SetMacAddressValue(val net.HardwareAddr) {
	panic("setting value with wrong data type")
}

func (b *baseInfoElement) SetStringValue(val string) {
	panic("setting value with wrong data type")
}

func (b *baseInfoElement) SetIPAddressValue(val net.IP) {
	panic("setting value with wrong data type")
}

func (b *baseInfoElement) GetLength() int {
	return int(b.element.Len)
}

type OctetArrayInfoElement struct {
	value []byte
	baseInfoElement
}

func NewOctetArrayInfoElement(element *InfoElement, val []byte) *OctetArrayInfoElement {
	infoElem := &OctetArrayInfoElement{
		value: val,
	}
	infoElem.element = element
	return infoElem
}

func (a *OctetArrayInfoElement) GetOctetArrayValue() []byte {
	return a.value
}

func (a *OctetArrayInfoElement) GetLength() int {
	if a.element.Len < VariableLength {
		return int(a.element.Len)
	}
	if len(a.value) < 255 {
		return len(a.value) + 1
	} else {
		return len(a.value) + 3
	}
}

func (a *OctetArrayInfoElement) SetOctetArrayValue(val []byte) {
	a.value = val
}

func (a *OctetArrayInfoElement) IsValueEmpty() bool {
	return a.value == nil
}

func (a *OctetArrayInfoElement) ResetValue() {
	a.value = nil
}

type Unsigned8InfoElement struct {
	value uint8
	baseInfoElement
}

func NewUnsigned8InfoElement(element *InfoElement, val uint8) *Unsigned8InfoElement {
	infoElem := &Unsigned8InfoElement{
		value: val,
	}
	infoElem.element = element
	return infoElem
}

func (u8 *Unsigned8InfoElement) GetUnsigned8Value() uint8 {
	return u8.value
}

func (u8 *Unsigned8InfoElement) SetUnsigned8Value(val uint8) {
	u8.value = val
}

func (u8 *Unsigned8InfoElement) IsValueEmpty() bool {
	return u8.value == 0
}

func (u8 *Unsigned8InfoElement) ResetValue() {
	u8.value = 0
}

type Unsigned16InfoElement struct {
	value uint16
	baseInfoElement
}

func NewUnsigned16InfoElement(element *InfoElement, val uint16) *Unsigned16InfoElement {
	infoElem := &Unsigned16InfoElement{
		value: val,
	}
	infoElem.element = element
	return infoElem
}

func (u16 *Unsigned16InfoElement) GetUnsigned16Value() uint16 {
	return u16.value
}

func (u16 *Unsigned16InfoElement) SetUnsigned16Value(val uint16) {
	u16.value = val
}

func (u16 *Unsigned16InfoElement) IsValueEmpty() bool {
	return u16.value == 0
}

func (u16 *Unsigned16InfoElement) ResetValue() {
	u16.value = 0
}

type Unsigned32InfoElement struct {
	value uint32
	baseInfoElement
}

func NewUnsigned32InfoElement(element *InfoElement, val uint32) *Unsigned32InfoElement {
	infoElem := &Unsigned32InfoElement{
		value: val,
	}
	infoElem.element = element
	return infoElem
}

func (u32 *Unsigned32InfoElement) GetUnsigned32Value() uint32 {
	return u32.value
}

func (u32 *Unsigned32InfoElement) SetUnsigned32Value(val uint32) {
	u32.value = val
}

func (u32 *Unsigned32InfoElement) IsValueEmpty() bool {
	return u32.value == 0
}

func (u32 *Unsigned32InfoElement) ResetValue() {
	u32.value = 0
}

type Unsigned64InfoElement struct {
	value uint64
	baseInfoElement
}

func NewUnsigned64InfoElement(element *InfoElement, val uint64) *Unsigned64InfoElement {
	infoElem := &Unsigned64InfoElement{
		value: val,
	}
	infoElem.element = element
	return infoElem
}

func (u64 *Unsigned64InfoElement) GetUnsigned64Value() uint64 {
	return u64.value
}

func (u64 *Unsigned64InfoElement) SetUnsigned64Value(val uint64) {
	u64.value = val
}

func (u64 *Unsigned64InfoElement) IsValueEmpty() bool {
	return u64.value == 0
}

func (u64 *Unsigned64InfoElement) ResetValue() {
	u64.value = 0
}

type Signed8InfoElement struct {
	value int8
	baseInfoElement
}

func NewSigned8InfoElement(element *InfoElement, val int8) *Signed8InfoElement {
	infoElem := &Signed8InfoElement{
		value: val,
	}
	infoElem.element = element
	return infoElem
}

func (i8 *Signed8InfoElement) GetSigned8Value() int8 {
	return i8.value
}

func (i8 *Signed8InfoElement) SetSigned8Value(val int8) {
	i8.value = val
}

func (i8 *Signed8InfoElement) IsValueEmpty() bool {
	return i8.value == 0
}

func (i8 *Signed8InfoElement) ResetValue() {
	i8.value = 0
}

type Signed16InfoElement struct {
	value int16
	baseInfoElement
}

func NewSigned16InfoElement(element *InfoElement, val int16) *Signed16InfoElement {
	infoElem := &Signed16InfoElement{
		value: val,
	}
	infoElem.element = element
	return infoElem
}

func (i16 *Signed16InfoElement) GetSigned16Value() int16 {
	return i16.value
}

func (i16 *Signed16InfoElement) SetSigned16Value(val int16) {
	i16.value = val
}

func (i16 *Signed16InfoElement) IsValueEmpty() bool {
	return i16.value == 0
}

func (i16 *Signed16InfoElement) ResetValue() {
	i16.value = 0
}

type Signed32InfoElement struct {
	value int32
	baseInfoElement
}

func NewSigned32InfoElement(element *InfoElement, val int32) *Signed32InfoElement {
	infoElem := &Signed32InfoElement{
		value: val,
	}
	infoElem.element = element
	return infoElem
}

func (i32 *Signed32InfoElement) GetSigned32Value() int32 {
	return i32.value
}

func (i32 *Signed32InfoElement) SetSigned32Value(val int32) {
	i32.value = val
}

func (i32 *Signed32InfoElement) IsValueEmpty() bool {
	return i32.value == 0
}

func (i32 *Signed32InfoElement) ResetValue() {
	i32.value = 0
}

type Signed64InfoElement struct {
	value int64
	baseInfoElement
}

func NewSigned64InfoElement(element *InfoElement, val int64) *Signed64InfoElement {
	infoElem := &Signed64InfoElement{
		value: val,
	}
	infoElem.element = element
	return infoElem
}

func (i64 *Signed64InfoElement) GetSigned64Value() int64 {
	return i64.value
}

func (i64 *Signed64InfoElement) SetSigned64Value(val int64) {
	i64.value = val
}

func (i64 *Signed64InfoElement) IsValueEmpty() bool {
	return i64.value == 0
}

func (i64 *Signed64InfoElement) ResetValue() {
	i64.value = 0
}

type Float32InfoElement struct {
	value float32
	baseInfoElement
}

func NewFloat32InfoElement(element *InfoElement, val float32) *Float32InfoElement {
	infoElem := &Float32InfoElement{
		value: val,
	}
	infoElem.element = element
	return infoElem
}

func (f32 *Float32InfoElement) GetFloat32Value() float32 {
	return f32.value
}

func (f32 *Float32InfoElement) SetFloat32Value(val float32) {
	f32.value = val
}

func (f32 *Float32InfoElement) IsValueEmpty() bool {
	return f32.value == 0
}

func (f32 *Float32InfoElement) ResetValue() {
	f32.value = 0
}

type Float64InfoElement struct {
	value float64
	baseInfoElement
}

func NewFloat64InfoElement(element *InfoElement, val float64) *Float64InfoElement {
	infoElem := &Float64InfoElement{
		value: val,
	}
	infoElem.element = element
	return infoElem
}

func (f64 *Float64InfoElement) GetFloat64Value() float64 {
	return f64.value
}

func (f64 *Float64InfoElement) SetFloat64Value(val float64) {
	f64.value = val
}

func (f64 *Float64InfoElement) IsValueEmpty() bool {
	return f64.value == 0
}

func (f64 *Float64InfoElement) ResetValue() {
	f64.value = 0
}

type BooleanInfoElement struct {
	value bool
	baseInfoElement
}

func NewBoolInfoElement(element *InfoElement, val bool) *BooleanInfoElement {
	infoElem := &BooleanInfoElement{
		value: val,
	}
	infoElem.element = element
	return infoElem
}

func (b *BooleanInfoElement) GetBooleanValue() bool {
	return b.value
}

func (b *BooleanInfoElement) SetBooleanValue(val bool) {
	b.value = val
}

func (b *BooleanInfoElement) IsValueEmpty() bool {
	return !b.value
}

func (b *BooleanInfoElement) ResetValue() {
	b.value = false
}

type MacAddressInfoElement struct {
	value net.HardwareAddr
	baseInfoElement
}

func NewMacAddressInfoElement(element *InfoElement, val net.HardwareAddr) *MacAddressInfoElement {
	infoElem := &MacAddressInfoElement{
		value: val,
	}
	infoElem.element = element
	return infoElem
}

func (mac *MacAddressInfoElement) GetMacAddressValue() net.HardwareAddr {
	return mac.value
}

func (mac *MacAddressInfoElement) SetMacAddressValue(val net.HardwareAddr) {
	mac.value = val
}

func (mac *MacAddressInfoElement) IsValueEmpty() bool {
	return mac.value == nil
}

func (mac *MacAddressInfoElement) ResetValue() {
	mac.value = nil
}

type StringInfoElement struct {
	baseInfoElement
	value string
}

func NewStringInfoElement(element *InfoElement, val string) *StringInfoElement {
	infoElem := &StringInfoElement{
		value: val,
	}
	infoElem.element = element
	return infoElem
}

func (s *StringInfoElement) GetStringValue() string {
	return s.value
}

func (s *StringInfoElement) GetLength() int {
	if len(s.value) < 255 {
		return len(s.value) + 1
	} else {
		return len(s.value) + 3
	}
}

func (s *StringInfoElement) SetStringValue(val string) {
	s.value = val
}

func (s *StringInfoElement) IsValueEmpty() bool {
	return s.value == ""
}

func (s *StringInfoElement) ResetValue() {
	s.value = ""
}

type DateTimeSecondsInfoElement struct {
	value uint32
	baseInfoElement
}

func NewDateTimeSecondsInfoElement(element *InfoElement, val uint32) *DateTimeSecondsInfoElement {
	infoElem := &DateTimeSecondsInfoElement{
		value: val,
	}
	infoElem.element = element
	return infoElem
}

func (dsec *DateTimeSecondsInfoElement) GetUnsigned32Value() uint32 {
	return dsec.value
}

func (dsec *DateTimeSecondsInfoElement) SetUnsigned32Value(val uint32) {
	dsec.value = val
}

func (dsec *DateTimeSecondsInfoElement) IsValueEmpty() bool {
	return dsec.value == 0
}

func (dsec *DateTimeSecondsInfoElement) ResetValue() {
	dsec.value = 0
}

type DateTimeMillisecondsInfoElement struct {
	value uint64
	baseInfoElement
}

func NewDateTimeMillisecondsInfoElement(element *InfoElement, val uint64) *DateTimeMillisecondsInfoElement {
	infoElem := &DateTimeMillisecondsInfoElement{
		value: val,
	}
	infoElem.element = element
	return infoElem
}

func (dmsec *DateTimeMillisecondsInfoElement) GetUnsigned64Value() uint64 {
	return dmsec.value
}

func (dmsec *DateTimeMillisecondsInfoElement) SetUnsigned64Value(val uint64) {
	dmsec.value = val
}

func (dmsec *DateTimeMillisecondsInfoElement) IsValueEmpty() bool {
	return dmsec.value == 0
}

func (dmsec *DateTimeMillisecondsInfoElement) ResetValue() {
	dmsec.value = 0
}

type IPAddressInfoElement struct {
	baseInfoElement
	value net.IP
}

func NewIPAddressInfoElement(element *InfoElement, val net.IP) *IPAddressInfoElement {
	infoElem := &IPAddressInfoElement{
		value: val,
	}
	infoElem.element = element
	return infoElem
}

func (ip *IPAddressInfoElement) GetIPAddressValue() net.IP {
	return ip.value
}

func (ip *IPAddressInfoElement) SetIPAddressValue(val net.IP) {
	ip.value = val
}

func (ip *IPAddressInfoElement) IsValueEmpty() bool {
	return ip.value == nil
}

func (ip *IPAddressInfoElement) ResetValue() {
	ip.value = nil
}

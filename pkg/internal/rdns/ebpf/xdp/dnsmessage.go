package xdp

const (
	Type_A               = 1
	Type_NS              = 2
	Type_MD              = 3
	Type_MF              = 4
	Type_CNAME           = 5
	Type_SOA             = 6
	Type_MB              = 7
	Type_MG              = 8
	Type_MR              = 9
	Type_NULL            = 10
	Type_WKS             = 11
	Type_PTR             = 12
	Type_HINFO           = 13
	Type_MINFO           = 14
	Type_MX              = 15
	Type_TXT             = 16
)

type question struct {
	qName string
	qType uint16
	qClass uint16
}

type record struct {
	name string
	typ uint16
	class uint16
	ttl uint32
	data []byte
}

type dnsMessage struct {
	id uint16
	flagsHi uint8
	flagsLo uint8

	questions []*question

	answers []*record
}

func getBit(word uint8, offset uint8) bool {
	return ((word >> offset) & 0x1) == 1
}

func (d *dnsMessage) Id() uint16 {
	return d.id
}

func (d *dnsMessage) IsQuery() bool {
	return getBit(d.flagsHi, 7)
}

func (d *dnsMessage) Opcode() uint8 {
	return (d.flagsHi >> 3) & 0xf
}

func (d *dnsMessage) AuthoritativeAnswer() bool {
	return getBit(d.flagsHi, 2)
}

func (d *dnsMessage) Truncation() bool {
	return getBit(d.flagsHi, 1)
}

func (d *dnsMessage) RecursionDesired() bool {
	return getBit(d.flagsHi, 0)
}

func (d *dnsMessage) RecursionAvailable() bool {
	return getBit(d.flagsLo, 7)
}

func (d *dnsMessage) Z() uint8 {
	return (d.flagsLo >> 4) & 0x7
}

func (d *dnsMessage) RCode() uint8 {
	return d.flagsLo & 0xf
}

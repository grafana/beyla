package xdp

// types here are mostly used for debugging purposes
// TODO: consider removing some types and functions here to simplify the code, as they remain mostly unused

const (
	TypeA     = 1
	TypeNS    = 2
	TypeMD    = 3
	TypeMF    = 4
	TypeCNAME = 5
	TypeSOA   = 6
	TypeMB    = 7
	TypeMG    = 8
	TypeMR    = 9
	TypeNULL  = 10
	TypeWKS   = 11
	TypePTR   = 12
	TypeHINFO = 13
	TypeMINFO = 14
	TypeMX    = 15
	TypeTXT   = 16
)

type question struct {
	qName  string
	qType  uint16
	qClass uint16
}

type record struct {
	name  string
	typ   uint16
	class uint16
	ttl   uint32
	data  []byte
}

type dnsMessage struct {
	id      uint16
	flagsHi uint8
	flagsLo uint8

	questions []*question

	answers []*record
}

func getBit(word uint8, offset uint8) bool {
	return ((word >> offset) & 0x1) == 1
}

func (d *dnsMessage) ID() uint16 {
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

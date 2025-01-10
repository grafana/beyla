package ebpf

const (
	// DirectionUnset is a convenience value to specify an unset/removed direction field
	DirectionUnset = 0xFF
	// DirectionIngress and DirectionEgress values according to field 61 in https://www.iana.org/assignments/ipfix/ipfix.xhtml
	DirectionIngress = 0
	DirectionEgress  = 1

	// InitiatorSrc and InitiatorDst values set accordingly to flows_common.h definition
	InitiatorSrc = 1
	InitiatorDst = 2

	InterfaceUnset = 0xFFFFFFFF
)

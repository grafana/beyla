package tcmanager

import (
	"context"

	"github.com/cilium/ebpf"
)

type AttachmentType uint8

const (
	AttachmentEgress = AttachmentType(iota)
	AttachmentIngress
)

type TCManager interface {
	Init(ctx context.Context)
	AddProgram(name string, prog *ebpf.Program, attachment AttachmentType)
	RemoveProgram(name string)
	InterfaceName(ifaceIndex int) (string, bool)
	SetInterfaceFilter(filter *InterfaceFilter)
}


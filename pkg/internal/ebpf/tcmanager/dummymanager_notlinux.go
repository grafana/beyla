//go:build !linux

package tcmanager

import (
	"github.com/cilium/ebpf"
)

type dummyManager struct{}

func NewTCXManager() TCManager {
	return &dummyManager{}
}

func NewNetlinkManager() TCManager {
	return &dummyManager{}
}

func (d *dummyManager) Shutdown()                                              {}
func (d *dummyManager) AddProgram(_ string, _ *ebpf.Program, _ AttachmentType) {}
func (d *dummyManager) RemoveProgram(_ string)                                 {}
func (d *dummyManager) InterfaceName(_ int) (string, bool)                     { return "", false }
func (d *dummyManager) SetInterfaceManager(_ *InterfaceManager)                {}
func (d *dummyManager) Errors() chan error                                     { return nil }

func EnsureCiliumCompatibility(_ TCBackend) error { return nil }

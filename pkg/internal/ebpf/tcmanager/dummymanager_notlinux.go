//go:build !linux

package tcmanager

import (
	"context"
	"time"

	"github.com/cilium/ebpf"
)

type dummyManager struct{}

func NewTCXManager() TCManager {
	return &dummyManager{}
}

func NewNetlinkManager() TCManager {
	return &dummyManager{}
}

func (d *dummyManager) Start(_ context.Context)                                {}
func (d *dummyManager) Stop()                                                  {}
func (d *dummyManager) AddProgram(_ string, _ *ebpf.Program, _ AttachmentType) {}
func (d *dummyManager) RemoveProgram(_ string)                                 {}
func (d *dummyManager) InterfaceName(_ int) (string, bool)                     { return "", false }
func (d *dummyManager) SetInterfaceFilter(_ *InterfaceFilter)                  {}
func (d *dummyManager) SetMonitorMode(_ MonitorMode)                           {}
func (d *dummyManager) SetChannelBufferLen(_ int)                              {}
func (d *dummyManager) SetPollPeriod(_ time.Duration)                          {}

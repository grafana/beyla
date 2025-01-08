// line below avoids linter errors on Mac
// nolint:unused
package tcmanager

import (
	"fmt"
	"strings"
	"time"

	"github.com/cilium/ebpf"
)

type TCBackend uint8

const (
	TCBackendTC = TCBackend(iota + 1)
	TCBackendTCX
)

type AttachmentType uint8

const (
	AttachmentEgress = AttachmentType(iota)
	AttachmentIngress
)

type MonitorMode uint8

const (
	MonitorPoll = MonitorMode(iota)
	MonitorWatch
)

const DefaultMonitorMode = MonitorMode(MonitorWatch)
const DefaultChannelBufferLen = 10
const DefaultPollPeriod = 10 * time.Second

type TCManager interface {
	Shutdown()
	AddProgram(name string, prog *ebpf.Program, attachment AttachmentType)
	RemoveProgram(name string)
	SetInterfaceManager(im *InterfaceManager)
}

func NewTCManager(backend TCBackend) TCManager {
	switch backend {
	case TCBackendTC:
		return NewNetlinkManager()
	case TCBackendTCX:
		return NewTCXManager()
	}

	return NewNetlinkManager() // default
}

func (b *TCBackend) UnmarshalText(text []byte) error {
	switch strings.TrimSpace(string(text)) {
	case "tc":
		*b = TCBackendTC
		return nil
	case "tcx":
		*b = TCBackendTCX
		return nil
	}

	return fmt.Errorf("invalid TCBakend value: '%s'", text)
}

func (b TCBackend) Valid() bool {
	switch b {
	case TCBackendTC, TCBackendTCX:
		return true
	}

	return false
}

// line below avoids linter errors on Mac
package tcmanager

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

type TCBackend uint8

const (
	TCBackendTC = TCBackend(iota + 1)
	TCBackendTCX
	TCBackendAuto
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

const (
	DefaultMonitorMode      = MonitorWatch
	DefaultChannelBufferLen = 10
	DefaultPollPeriod       = 10 * time.Second
)

type TCManager interface {
	Shutdown()
	AddProgram(name string, prog *ebpf.Program, attachment AttachmentType)
	RemoveProgram(name string)
	SetInterfaceManager(im *InterfaceManager)
	Errors() chan error
}

func newTCManagerAuto() TCManager {
	log := slog.With("component", "tc_manager")

	log.Debug("Auto detecting TCX support")

	if IsTCXSupported() {
		log.Debug("TCX support detected")
		return NewTCXManager()
	}

	log.Debug("TCX not supported, using netlink")

	return NewNetlinkManager()
}

func NewTCManager(backend TCBackend) TCManager {
	switch backend {
	case TCBackendTC:
		return NewNetlinkManager()
	case TCBackendTCX:
		return NewTCXManager()
	case TCBackendAuto:
		return newTCManagerAuto()
	}

	return newTCManagerAuto() // default
}

func (b *TCBackend) UnmarshalText(text []byte) error {
	switch strings.TrimSpace(string(text)) {
	case "tc":
		*b = TCBackendTC
		return nil
	case "tcx":
		*b = TCBackendTCX
		return nil
	case "auto":
		*b = TCBackendAuto
		return nil
	}

	return fmt.Errorf("invalid TCBakend value: '%s'", text)
}

func (b TCBackend) MarshalText() ([]byte, error) {
	switch b {
	case TCBackendTC:
		return []byte("tc"), nil
	case TCBackendTCX:
		return []byte("tcx"), nil
	case TCBackendAuto:
		return []byte("auto"), nil
	}

	return nil, fmt.Errorf("invalid TCBakend value: %d", b)
}

func (b TCBackend) Valid() bool {
	switch b {
	case TCBackendTC, TCBackendTCX, TCBackendAuto:
		return true
	}

	return false
}

var IsTCXSupported = sync.OnceValue(func() bool {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.SchedCLS,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "Apache-2.0",
	})
	if err != nil {
		return false
	}

	defer prog.Close()

	l, err := link.AttachTCX(link.TCXOptions{
		Program:   prog,
		Attach:    ebpf.AttachTCXIngress,
		Interface: 1, // lo
		Anchor:    link.Tail(),
	})
	if err != nil {
		return false
	}

	if err := l.Close(); err != nil {
		return false
	}

	return true
})

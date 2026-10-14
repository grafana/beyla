// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// line below avoids linter errors on Mac
package tcmanager // import "go.opentelemetry.io/obi/pkg/internal/ebpf/tcmanager"

import (
	"log/slog"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/obi/pkg/config"
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

func NewTCManager(backend config.TCBackend) TCManager {
	switch backend {
	case config.TCBackendTC:
		return NewNetlinkManager()
	case config.TCBackendTCX:
		return NewTCXManager()
	case config.TCBackendAuto:
		return newTCManagerAuto()
	}

	return newTCManagerAuto() // default
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

package tcmanager

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"

	"github.com/grafana/beyla/pkg/internal/netolly/ifaces"
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
	Start(ctx context.Context)
	Stop()
	AddProgram(name string, prog *ebpf.Program, attachment AttachmentType)
	RemoveProgram(name string)
	InterfaceName(ifaceIndex int) (string, bool)
	SetInterfaceFilter(filter *InterfaceFilter)
	SetMonitorMode(mode MonitorMode)
	SetChannelBufferLen(channelBufferLen int)
	SetPollPeriod(period time.Duration)
}

type tcManagerBase struct {
	filter           *InterfaceFilter
	monitorMode      MonitorMode
	channelBufferLen int
	pollPeriod       time.Duration
	registerer       *ifaces.Registerer
	log              *slog.Logger
	mutex            sync.Mutex
	wg               sync.WaitGroup
}

func newTCManagerBase(component string) tcManagerBase {
	return tcManagerBase{
		filter:           nil,
		monitorMode:      DefaultMonitorMode,
		channelBufferLen: DefaultChannelBufferLen,
		pollPeriod:       DefaultPollPeriod,
		registerer:       nil,
		log:              slog.With("component", component),
		mutex:            sync.Mutex{},
		wg:               sync.WaitGroup{},
	}
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

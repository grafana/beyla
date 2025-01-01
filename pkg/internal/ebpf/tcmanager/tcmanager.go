package tcmanager

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/cilium/ebpf"

	"github.com/grafana/beyla/pkg/internal/netolly/ifaces"
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

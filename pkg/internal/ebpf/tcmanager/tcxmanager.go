//go:build linux

package tcmanager

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/grafana/beyla/pkg/internal/netolly/ifaces"
)

type attachedProg struct {
	prog       *ebpf.Program
	attachType AttachmentType
}

type tcxInterfaceMap map[int]ifaces.Interface
type tcxProgramsMap map[string]*attachedProg
type tcxLinksMap map[int][]link.Link

type tcxManager struct {
	tcManagerBase
	interfaces tcxInterfaceMap
	programs   tcxProgramsMap
	links      tcxLinksMap
}

func NewTCXManager() TCManager {
	return &tcxManager{
		tcManagerBase: newTCManagerBase("tcx_manager"),
		interfaces:    tcxInterfaceMap{},
		programs:      tcxProgramsMap{},
		links:         tcxLinksMap{},
	}
}

func tcxAttachType(attachment AttachmentType) (ebpf.AttachType, error) {
	switch attachment {
	case AttachmentEgress:
		return ebpf.AttachTCXEgress, nil
	case AttachmentIngress:
		return ebpf.AttachTCXIngress, nil
	}

	return 0, fmt.Errorf("invalid attachment type: %d", attachment)
}

func (tcx *tcxManager) Start(ctx context.Context) {
	if tcx.registerer != nil {
		return
	}

	informer := ifaces.NewWatcher(tcx.channelBufferLen)
	registerer := ifaces.NewRegisterer(informer, tcx.channelBufferLen)

	ifaceEvents, err := registerer.Subscribe(ctx)

	if err != nil {
		tcx.log.Error("instantiating interfaces' informer", "error", err)
		return
	}

	tcx.registerer = registerer

	tcx.wg.Add(1)

	go func() {
		for {
			select {
			case <-ctx.Done():
				tcx.shutdown()
				tcx.wg.Done()
				return
			case event := <-ifaceEvents:
				tcx.log.Debug("received event", "event", event)
				switch event.Type {
				case ifaces.EventAdded:
					tcx.onInterfaceAdded(event.Interface)
				case ifaces.EventDeleted:
					tcx.onInterfaceRemoved(event.Interface)
				default:
					tcx.log.Warn("unknown event type", "event", event)
				}
			}
		}
	}()
}

func (tcx *tcxManager) Stop() {
	tcx.wg.Wait()
}

func (tcx *tcxManager) shutdown() {
	tcx.log.Debug("TCX initiated shutdown")

	tcx.mutex.Lock()
	defer tcx.mutex.Unlock()

	for _, iface := range tcx.interfaces {
		tcx.removeInterfaceLocked(iface)
	}

	tcx.registerer = nil
	tcx.interfaces = tcxInterfaceMap{}
	tcx.programs = tcxProgramsMap{}
	tcx.links = tcxLinksMap{}

	tcx.log.Debug("TCX completed shutdown")
}

func (tcx *tcxManager) AddProgram(name string, prog *ebpf.Program, attachment AttachmentType) {
	tcx.mutex.Lock()
	defer tcx.mutex.Unlock()

	p := &attachedProg{
		prog:       prog,
		attachType: attachment,
	}

	tcx.programs[name] = p
	tcx.attachProgramLocked(name, p)
}

func (tcx *tcxManager) RemoveProgram(name string) {
	delete(tcx.programs, name)
}

func (tcx *tcxManager) attachProgramLocked(_ string, prog *attachedProg) {
	for iface := range tcx.interfaces {
		tcx.attachProgramToIfaceLocked(prog, iface)
	}
}

func (tcx *tcxManager) attachProgramToIfaceLocked(prog *attachedProg, iface int) {
	if prog == nil {
		return
	}

	attachType, err := tcxAttachType(prog.attachType)

	if err != nil {
		tcx.log.Error("Error attaching program", "error", err)
		return
	}

	link, err := link.AttachTCX(link.TCXOptions{
		Program:   prog.prog,
		Attach:    attachType,
		Interface: iface,
		Anchor:    link.Head(),
	})

	if err != nil {
		tcx.log.Error("Error attaching tcx", "error", err)
		return
	}

	tcx.links[iface] = append(tcx.links[iface], link)
}

func (tcx *tcxManager) onInterfaceAdded(iface ifaces.Interface) {
	tcx.mutex.Lock()
	defer tcx.mutex.Unlock()

	if tcx.filter != nil && !tcx.filter.IsAllowed(iface.Name) {
		tcx.log.Debug("Interface now allowed", "interface", iface.Name)
		return
	}

	tcx.interfaces[iface.Index] = iface

	for _, prog := range tcx.programs {
		tcx.attachProgramToIfaceLocked(prog, iface.Index)
	}
}

func (tcx *tcxManager) onInterfaceRemoved(iface ifaces.Interface) {
	tcx.mutex.Lock()
	defer tcx.mutex.Unlock()

	tcx.removeInterfaceLocked(iface)
}

func (tcx *tcxManager) removeInterfaceLocked(iface ifaces.Interface) {
	tcx.closeLinksLocked(iface)

	delete(tcx.interfaces, iface.Index)
}

func (tcx *tcxManager) closeLinksLocked(iface ifaces.Interface) {
	links, ok := tcx.links[iface.Index]

	if !ok {
		return
	}

	for _, link := range links {
		link.Close()
	}

	delete(tcx.links, iface.Index)
}

func (tcx *tcxManager) InterfaceName(ifaceIndex int) (string, bool) {
	tcx.mutex.Lock()
	defer tcx.mutex.Unlock()

	if iface, ok := tcx.interfaces[ifaceIndex]; ok {
		return iface.Name, true
	}

	return "", false
}

func (tcx *tcxManager) SetInterfaceFilter(filter *InterfaceFilter) {
	tcx.mutex.Lock()
	defer tcx.mutex.Unlock()

	tcx.filter = filter
}

func (tcx *tcxManager) SetMonitorMode(mode MonitorMode) {
	tcx.mutex.Lock()
	defer tcx.mutex.Unlock()

	tcx.monitorMode = mode
}

func (tcx *tcxManager) SetChannelBufferLen(channelBufferLen int) {
	tcx.mutex.Lock()
	defer tcx.mutex.Unlock()

	tcx.channelBufferLen = channelBufferLen
}

func (tcx *tcxManager) SetPollPeriod(period time.Duration) {
	tcx.mutex.Lock()
	defer tcx.mutex.Unlock()

	tcx.pollPeriod = period
}

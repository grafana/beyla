//go:build linux

package tcmanager

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/netolly/ifaces"
)

type attachedProg struct {
	*ebpf.Program
	attachType AttachmentType
	name       string
}

type ifaceLink struct {
	link.Link
	progName string
	iface    int
}

type tcxManager struct {
	ifaceManager      *InterfaceManager
	programs          []*attachedProg
	links             []*ifaceLink
	log               *slog.Logger
	mutex             sync.Mutex
	addedCallbackID   uint64
	removedCallbackID uint64
	errorCallbackID   uint64
	errorCh           chan error
}

func NewTCXManager() TCManager {
	return &tcxManager{
		ifaceManager: nil,
		programs:     []*attachedProg{},
		links:        []*ifaceLink{},
		log:          slog.With("component", "tcx_manager"),
		mutex:        sync.Mutex{},
		errorCh:      make(chan error),
	}
}

func (tcx *tcxManager) Errors() chan error {
	return tcx.errorCh
}

func (tcx *tcxManager) emitError(msg string, args ...any) {
	tcx.log.Error(msg, args...)

	formattedArgs := fmt.Sprint(args...)
	compositeError := fmt.Errorf("%s: %s", msg, formattedArgs)

	tcx.errorCh <- compositeError
}

func (tcx *tcxManager) SetInterfaceManager(im *InterfaceManager) {
	tcx.mutex.Lock()
	defer tcx.mutex.Unlock()

	if tcx.ifaceManager != nil {
		tcx.ifaceManager.RemoveCallback(tcx.addedCallbackID)
		tcx.ifaceManager.RemoveCallback(tcx.removedCallbackID)
		tcx.ifaceManager.RemoveCallback(tcx.errorCallbackID)
	}

	if im != nil {
		tcx.addedCallbackID = im.AddInterfaceAddedCallback(func(i *ifaces.Interface) { tcx.onInterfaceAdded(i) })
		tcx.removedCallbackID = im.AddInterfaceRemovedCallback(func(i *ifaces.Interface) { tcx.onInterfaceRemoved(i) })
		tcx.errorCallbackID = im.AddErrorCallback(func(err error) { tcx.onIfaceManagerError(err) })
	}

	tcx.ifaceManager = im
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

func (tcx *tcxManager) Shutdown() {
	tcx.log.Debug("TCX initiated shutdown")

	tcx.mutex.Lock()
	defer tcx.mutex.Unlock()

	if tcx.ifaceManager != nil {
		for _, iface := range tcx.ifaceManager.Interfaces() {
			tcx.closeLinksLocked(iface)
		}
	}

	tcx.programs = []*attachedProg{}
	tcx.links = []*ifaceLink{}

	close(tcx.errorCh)

	tcx.log.Debug("TCX completed shutdown")
}

func (tcx *tcxManager) AddProgram(name string, prog *ebpf.Program, attachment AttachmentType) {
	tcx.mutex.Lock()
	defer tcx.mutex.Unlock()

	p := &attachedProg{
		Program:    prog,
		attachType: attachment,
		name:       name,
	}

	tcx.programs = append(tcx.programs, p)
	tcx.attachProgramLocked(p)
}

func (tcx *tcxManager) attachProgramLocked(prog *attachedProg) {
	if tcx.ifaceManager == nil {
		return
	}

	for iface := range tcx.ifaceManager.Interfaces() {
		tcx.attachProgramToIfaceLocked(prog, iface)
	}
}

func (tcx *tcxManager) RemoveProgram(name string) {
	tcx.mutex.Lock()
	defer tcx.mutex.Unlock()

	tcx.unlinkProgramLocked(name)
	tcx.removeProgramLocked(name)
}

func (tcx *tcxManager) removeProgramLocked(name string) {
	closeProgs := func(prog *attachedProg) {
		if prog.name != name {
			return
		}

		if err := prog.Close(); err != nil {
			tcx.emitError("Failed to close program", "program", prog, "error", err)
		}
	}

	apply(tcx.programs, closeProgs)
	tcx.programs = removeIf(tcx.programs, func(prog *attachedProg) bool { return prog.name == name })
}

func (tcx *tcxManager) unlinkProgramLocked(name string) {
	closeLinks := func(link *ifaceLink) {
		if link.progName != name {
			return
		}

		if err := link.Close(); err != nil {
			tcx.emitError("Failed to unlink program", "program", name, "error", err)
		}
	}

	apply(tcx.links, closeLinks)
	tcx.links = removeIf(tcx.links, func(link *ifaceLink) bool { return link.progName == name })
}

func (tcx *tcxManager) attachProgramToIfaceLocked(prog *attachedProg, iface int) {
	if prog == nil {
		return
	}

	attachType, err := tcxAttachType(prog.attachType)
	if err != nil {
		tcx.emitError("Error attaching program", "program", prog.name, "error", err)
		return
	}

	link, err := link.AttachTCX(link.TCXOptions{
		Program:   prog.Program,
		Attach:    attachType,
		Interface: iface,
		Anchor:    link.Head(),
	})
	if err != nil {
		tcx.emitError("Error attaching tcx", "error", err)
		return
	}

	tcx.links = append(tcx.links, &ifaceLink{Link: link, progName: prog.name, iface: iface})
}

func (tcx *tcxManager) onInterfaceAdded(iface *ifaces.Interface) {
	tcx.mutex.Lock()
	defer tcx.mutex.Unlock()

	for _, prog := range tcx.programs {
		tcx.attachProgramToIfaceLocked(prog, iface.Index)
	}
}

func (tcx *tcxManager) onInterfaceRemoved(iface *ifaces.Interface) {
	tcx.mutex.Lock()
	defer tcx.mutex.Unlock()

	tcx.closeLinksLocked(iface)
}

func (tcx *tcxManager) closeLinksLocked(iface *ifaces.Interface) {
	closeLinks := func(link *ifaceLink) {
		if link.iface == iface.Index {
			link.Close()
		}
	}

	apply(tcx.links, closeLinks)
	tcx.links = removeIf(tcx.links, func(l *ifaceLink) bool { return l.iface == iface.Index })
}

func (tcx *tcxManager) onIfaceManagerError(err error) {
	tcx.emitError("interface manager error", err)
}

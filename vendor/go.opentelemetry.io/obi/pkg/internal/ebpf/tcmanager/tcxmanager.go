// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package tcmanager // import "go.opentelemetry.io/obi/pkg/internal/ebpf/tcmanager"

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/internal/netolly/ifaces"
)

type attachedProg struct {
	*ebpf.Program
	attachType AttachmentType
	name       string
	closeFn    func() error
}

func (p *attachedProg) Close() error {
	return closeWith(p.closeFn, p.Program)
}

type ifaceLink struct {
	link.Link
	progName string
	iface    int
	closeFn  func() error
}

func (l *ifaceLink) Close() error {
	return closeWith(l.closeFn, l.Link)
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
	errors            errorReporter
	attachProgramFn   func(*attachedProg, int)
	shutdown          bool
}

func NewTCXManager() TCManager {
	tcx := &tcxManager{
		ifaceManager: nil,
		programs:     []*attachedProg{},
		links:        []*ifaceLink{},
		log:          slog.With("component", "tcx_manager"),
		mutex:        sync.Mutex{},
		errors:       newErrorReporter(),
	}
	tcx.attachProgramFn = tcx.attachProgramToIfaceLocked
	return tcx
}

func (tcx *tcxManager) Errors() chan error {
	return tcx.errors.ch
}

func (tcx *tcxManager) emitError(msg string, args ...any) {
	tcx.log.Error(msg, args...)

	formattedArgs := fmt.Sprint(args...)
	compositeError := fmt.Errorf("%s: %s", msg, formattedArgs)

	tcx.errors.enqueue(compositeError)
}

func (tcx *tcxManager) SetInterfaceManager(im *InterfaceManager) {
	tcx.mutex.Lock()
	defer tcx.mutex.Unlock()

	tcx.unregisterCallbacksLocked()

	if tcx.shutdown {
		return
	}

	if im != nil {
		tcx.addedCallbackID = im.AddInterfaceAddedCallback(func(i *ifaces.Interface) { tcx.onInterfaceAdded(i) })
		tcx.removedCallbackID = im.AddInterfaceRemovedCallback(func(i *ifaces.Interface) { tcx.onInterfaceRemoved(i) })
		tcx.errorCallbackID = im.AddErrorCallback(func(err error) { tcx.onIfaceManagerError(err) })
	}

	tcx.ifaceManager = im
}

func (tcx *tcxManager) unregisterCallbacksLocked() {
	if tcx.ifaceManager == nil {
		return
	}

	tcx.ifaceManager.RemoveCallback(tcx.addedCallbackID)
	tcx.ifaceManager.RemoveCallback(tcx.removedCallbackID)
	tcx.ifaceManager.RemoveCallback(tcx.errorCallbackID)
	tcx.ifaceManager = nil
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

	if tcx.shutdown {
		return
	}
	tcx.shutdown = true

	tcx.unregisterCallbacksLocked()
	tcx.cleanupLinksLocked()
	tcx.cleanupProgsLocked()
	tcx.errors.close()

	tcx.log.Debug("TCX completed shutdown")
}

func (tcx *tcxManager) AddProgram(name string, prog *ebpf.Program, attachment AttachmentType) {
	tcx.mutex.Lock()
	defer tcx.mutex.Unlock()
	if tcx.shutdown {
		return
	}

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
	if tcx.shutdown {
		return
	}

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

	switch {
	case err == nil:
		tcx.links = append(tcx.links, &ifaceLink{Link: link, progName: prog.name, iface: iface})
	case errors.Is(err, unix.EEXIST):
		tcx.log.Warn("Program already attached", "program", prog.name, "iface", iface)
	case errors.Is(err, unix.ENODEV):
		tcx.log.Warn(eNoDevMsg, "program", prog.name, "iface", iface)
	default:
		tcx.emitError("Error attaching tcx", "error", err)
	}
}

func (tcx *tcxManager) onInterfaceAdded(iface *ifaces.Interface) {
	tcx.mutex.Lock()
	defer tcx.mutex.Unlock()
	if tcx.shutdown {
		return
	}

	for _, prog := range tcx.programs {
		tcx.attachProgramFn(prog, iface.Index)
	}
}

func (tcx *tcxManager) onInterfaceRemoved(iface *ifaces.Interface) {
	tcx.mutex.Lock()
	defer tcx.mutex.Unlock()
	if tcx.shutdown {
		return
	}

	tcx.closeLinksLocked(iface)
}

func (tcx *tcxManager) closeLinksLocked(iface *ifaces.Interface) {
	closeLinks := func(link *ifaceLink) {
		if link.iface == iface.Index {
			if err := link.Close(); err != nil {
				tcx.emitError("Failed to unlink program", "program", link.progName,
					"iface", iface.Index, "error", err)
			}
		}
	}

	apply(tcx.links, closeLinks)
	tcx.links = removeIf(tcx.links, func(l *ifaceLink) bool { return l.iface == iface.Index })
}

func (tcx *tcxManager) cleanupLinksLocked() {
	for _, ifaceLink := range tcx.links {
		if err := ifaceLink.Close(); err != nil {
			tcx.emitError("Failed to unlink program", "program", ifaceLink.progName,
				"iface", ifaceLink.iface, "error", err)
		}
	}

	tcx.links = []*ifaceLink{}
}

func (tcx *tcxManager) cleanupProgsLocked() {
	for _, prog := range tcx.programs {
		tcx.log.Debug("closing tcx program", "name", prog.name)
		if err := prog.Close(); err != nil {
			tcx.emitError("Failed to close program", "program", prog.name, "error", err)
		}
	}

	tcx.programs = []*attachedProg{}
}

func (tcx *tcxManager) onIfaceManagerError(err error) {
	tcx.emitError("interface manager error", err)
}

//go:build linux

package tcmanager

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/netolly/ifaces"
)

var nextTCHandle = atomic.Uint32{}

func nextHandle() uint32 {
	// handles start at the 0xb310 value
	nextTCHandle.CompareAndSwap(0, 0xb310)
	return nextTCHandle.Add(1)
}

type netlinkProg struct {
	*ebpf.Program
	name       string
	attachType AttachmentType
}

type netlinkIface struct {
	*ifaces.Interface
	qdisc   *netlink.GenericQdisc
	filters []*netlink.BpfFilter
}

type netlinkIfaceMap map[int]*netlinkIface

type netlinkManager struct {
	ifaceManager      *InterfaceManager
	interfaces        netlinkIfaceMap
	programs          []*netlinkProg
	log               *slog.Logger
	mutex             sync.Mutex
	addedCallbackID   uint64
	removedCallbackID uint64
	errorCallbackID   uint64
	errorCh           chan error
}

func netlinkAttachType(attachment AttachmentType) (uint32, error) {
	switch attachment {
	case AttachmentEgress:
		return netlink.HANDLE_MIN_EGRESS, nil
	case AttachmentIngress:
		return netlink.HANDLE_MIN_INGRESS, nil
	}

	return 0, fmt.Errorf("invalid attachment type: %d", attachment)
}

func NewNetlinkManager() TCManager {
	return &netlinkManager{
		ifaceManager: nil,
		interfaces:   netlinkIfaceMap{},
		programs:     []*netlinkProg{},
		log:          slog.With("component", "tc_manager_netlink"),
		mutex:        sync.Mutex{},
		errorCh:      make(chan error),
	}
}

func (tc *netlinkManager) SetInterfaceManager(im *InterfaceManager) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	if tc.ifaceManager != nil {
		tc.ifaceManager.RemoveCallback(tc.addedCallbackID)
		tc.ifaceManager.RemoveCallback(tc.removedCallbackID)
		tc.ifaceManager.RemoveCallback(tc.errorCallbackID)
	}

	if im != nil {
		tc.addedCallbackID = im.AddInterfaceAddedCallback(func(i *ifaces.Interface) { tc.onInterfaceAdded(i) })
		tc.removedCallbackID = im.AddInterfaceRemovedCallback(func(i *ifaces.Interface) { tc.onInterfaceRemoved(i) })
		tc.errorCallbackID = im.AddErrorCallback(func(err error) { tc.onIfaceManagerError(err) })
	}

	tc.ifaceManager = im
}

func (tc *netlinkManager) Shutdown() {
	tc.log.Debug("TC initiated shutdown")

	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	tc.cleanupInterfacesLocked()
	tc.cleanupProgsLocked()

	close(tc.errorCh)

	tc.log.Debug("TC completed shutdown")
}

func (tc *netlinkManager) AddProgram(name string, prog *ebpf.Program, attachment AttachmentType) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	p := &netlinkProg{
		Program:    prog,
		name:       name,
		attachType: attachment,
	}

	tc.programs = append(tc.programs, p)
	tc.attachProgramLocked(p)
}

func (tc *netlinkManager) RemoveProgram(name string) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	tc.detachProgramLocked(name)
	tc.removeProgramLocked(name)
}

func (tc *netlinkManager) Errors() chan error {
	return tc.errorCh
}

func (tc *netlinkManager) attachProgramLocked(prog *netlinkProg) {
	for _, iface := range tc.interfaces {
		tc.attachProgramToIfaceLocked(prog, iface)
	}
}

func (tc *netlinkManager) attachProgramToIfaceLocked(prog *netlinkProg, iface *netlinkIface) {
	if prog == nil {
		return
	}

	attachType, err := netlinkAttachType(prog.attachType)
	if err != nil {
		tc.emitError("Error attaching program", "error", err)
		return
	}

	attrs := netlink.FilterAttrs{
		LinkIndex: iface.Index,
		Parent:    attachType,
		Handle:    nextHandle(),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}

	filter := &netlink.BpfFilter{
		FilterAttrs:  attrs,
		Fd:           prog.FD(),
		Name:         prog.name,
		DirectAction: true,
	}

	if err := netlink.FilterDel(filter); err == nil {
		tc.log.Warn("filter already existed. Deleted it", "filter", prog.name, "iface", iface)
	}

	if err := netlink.FilterAdd(filter); err != nil {
		if errors.Is(err, fs.ErrExist) {
			tc.log.Warn("filter already exists. Ignoring", "error", err)
		} else {
			tc.emitError("failed to create filter", err)
		}
	}

	iface.filters = append(iface.filters, filter)
}

func (tc *netlinkManager) detachProgramLocked(prog string) {
	for _, iface := range tc.interfaces {
		tc.detachProgramFromIfaceLocked(prog, iface)
	}
}

func (tc *netlinkManager) detachProgramFromIfaceLocked(prog string, iface *netlinkIface) {
	detach := func(filter *netlink.BpfFilter) {
		if filter.Name != prog {
			return
		}

		if err := netlink.FilterDel(filter); err != nil {
			tc.emitError("Failed to delete filter", "filter", prog, "error", err)
		}
	}

	apply(iface.filters, detach)
	iface.filters = removeIf(iface.filters, func(filter *netlink.BpfFilter) bool { return filter.Name == prog })
}

func (tc *netlinkManager) removeProgramLocked(name string) {
	closeProgs := func(prog *netlinkProg) {
		if prog.name != name {
			return
		}

		if err := prog.Close(); err != nil {
			tc.emitError("Failed to close program", "program", prog, "error", err)
		}
	}

	apply(tc.programs, closeProgs)
	tc.programs = removeIf(tc.programs, func(prog *netlinkProg) bool { return prog.name == name })
}

func (tc *netlinkManager) onInterfaceAdded(i *ifaces.Interface) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	qdisc := tc.installQdisc(i)

	if qdisc == nil {
		tc.log.Debug("Unable to install qdisc, ignoring interface", "interface", i.Name)
		return
	}

	iface := &netlinkIface{i, qdisc, []*netlink.BpfFilter{}}
	tc.interfaces[i.Index] = iface

	for _, prog := range tc.programs {
		tc.attachProgramToIfaceLocked(prog, iface)
	}
}

func (tc *netlinkManager) onInterfaceRemoved(iface *ifaces.Interface) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	// links, qdiscs and other associated resources are automatically removed
	// when an interface is removed, there's no need to explicitly remove them
	delete(tc.interfaces, iface.Index)
}

func (tc *netlinkManager) onIfaceManagerError(err error) {
	tc.emitError("interface manager error", err)
}

func (tc *netlinkManager) installQdisc(iface *ifaces.Interface) *netlink.GenericQdisc {
	link, err := netlink.LinkByIndex(iface.Index)
	if err != nil {
		tc.emitError("failed to lookup link device", "index", iface.Index, "name", iface.Name, "error", err)
		return nil
	}

	qdiscAttrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: qdiscAttrs,
		QdiscType:  "clsact",
	}

	if err := netlink.QdiscAdd(qdisc); err != nil {
		if errors.Is(err, fs.ErrExist) {
			tc.log.Warn("qdisc clsact already exists. Ignoring", "error", err)
		} else {
			tc.emitError("failed to create clsact qdisc on", "index", iface.Index, "name", iface.Name, "error", err)
			return nil
		}
	}

	return qdisc
}

func (tc *netlinkManager) cleanupInterfacesLocked() {
	for _, iface := range tc.interfaces {
		tc.cleanupFiltersLocked(iface)

		// make sure this happens only after cleaning up filters,
		// so that we don't remove 3rdparty filters
		tc.cleanupQdiscLocked(iface)
	}

	tc.interfaces = netlinkIfaceMap{}
}

func (tc *netlinkManager) cleanupFiltersLocked(iface *netlinkIface) {
	for _, filter := range iface.filters {
		tc.log.Debug("deleting filter", "interface", iface, "name", filter.Name)

		err := doIgnoreNoDev(netlink.FilterDel, netlink.Filter(filter))
		if err != nil {
			tc.emitError("deleting filter", "interface", iface,
				"filter", filter.Name, "error", err)
		}
	}
}

func (tc *netlinkManager) cleanupQdiscLocked(iface *netlinkIface) {
	if iface.qdisc == nil {
		return
	}

	hasEgressFilters := ifaceHasFilters(iface, netlink.HANDLE_MIN_EGRESS)
	hasIngressFilters := ifaceHasFilters(iface, netlink.HANDLE_MIN_INGRESS)

	if hasEgressFilters || hasIngressFilters {
		tc.log.Debug("not deleting Qdisc as it still has children", "interface", iface)
		return
	}

	tc.log.Debug("deleting Qdisc", "interface", iface)

	if err := doIgnoreNoDev(netlink.QdiscDel, netlink.Qdisc(iface.qdisc)); err != nil {
		tc.emitError("deleting qdisc", "error", err)
	}
}

func ifaceHasFilters(iface *netlinkIface, parent uint32) bool {
	link, err := netlink.LinkByIndex(iface.Index)
	if err != nil {
		return true // be conservative assume we have filters if we can't detect them
	}

	filters, err := netlink.FilterList(link, parent)
	if err != nil {
		return true // be conservative assume we have filters if we can't detect them
	}

	return len(filters) > 0
}

func (tc *netlinkManager) cleanupProgsLocked() {
	for _, prog := range tc.programs {
		tc.log.Debug("closing tc program", "name", prog.name)
		prog.Close()
	}

	tc.programs = []*netlinkProg{}
}

func (tc *netlinkManager) emitError(msg string, args ...any) {
	tc.log.Error(msg, args...)

	formattedArgs := fmt.Sprint(args...)
	compositeError := fmt.Errorf("%s: %s", msg, formattedArgs)

	tc.errorCh <- compositeError
}

// doIgnoreNoDev runs the provided syscall over the provided device and ignores the error
// if the cause is a non-existing device (just logs the error as debug).
// If the agent is deployed as part of the Network Metrics pipeline, normally
// undeploying the FlowCollector could cause the agent to try to remove resources
// from Pods that have been removed immediately before (e.g. flowlogs-pipeline or the
// console plugin), so we avoid logging some errors that would unnecessarily raise the
// user's attention.
// This function uses generics because the set of provided functions accept different argument
// types.
func doIgnoreNoDev[T any](sysCall func(T) error, dev T) error {
	if err := sysCall(dev); err != nil {
		if errors.Is(err, unix.ENODEV) {
			slog.Error("can't delete. Ignore this error if other pods or interfaces "+
				" are also being deleted at this moment. For example, if you are undeploying "+
				" a FlowCollector or Deployment where this agent is part of",
				"error", err)
		} else {
			return err
		}
	}
	return nil
}

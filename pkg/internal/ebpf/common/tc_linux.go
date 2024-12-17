//go:build linux

package ebpfcommon

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/grafana/beyla/pkg/internal/netolly/ifaces"
)

type TCLinks struct {
	Qdisc         *netlink.GenericQdisc
	EgressFilter  *netlink.BpfFilter
	IngressFilter *netlink.BpfFilter
}

func StartTCMonitorLoop(ctx context.Context, registerer *ifaces.Registerer, register func(iface ifaces.Interface), log *slog.Logger) {
	log.Debug("subscribing for network interface events")
	ifaceEvents, err := registerer.Subscribe(ctx)
	if err != nil {
		log.Error("instantiating interfaces' informer", "error", err)
		return
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				slog.Debug("stopping interfaces' listener")
				return
			case event := <-ifaceEvents:
				slog.Debug("received event", "event", event)
				switch event.Type {
				case ifaces.EventAdded:
					register(event.Interface)
				case ifaces.EventDeleted:
					// qdiscs, ingress and egress filters are automatically deleted so we don't need to
					// specifically detach them from the ebpfFetcher
				default:
					slog.Warn("unknown event type", "event", event)
				}
			}
		}
	}()
}

// Convenience function
func WatchAndRegisterTC(ctx context.Context, channelBufferLen int, register func(iface ifaces.Interface), log *slog.Logger) {
	log.Debug("listening for new interfaces: use watching")

	informer := ifaces.NewWatcher(channelBufferLen)
	registerer := ifaces.NewRegisterer(informer, channelBufferLen)
	StartTCMonitorLoop(ctx, registerer, register, log)
}

// Convenience function
func PollAndRegisterTC(ctx context.Context, channelBufferLen int, register func(iface ifaces.Interface), period time.Duration, log *slog.Logger) {
	log.Debug("listening for new interfaces: use polling", "period", period)

	informer := ifaces.NewPoller(period, channelBufferLen)
	registerer := ifaces.NewRegisterer(informer, channelBufferLen)
	StartTCMonitorLoop(ctx, registerer, register, log)
}

func GetClsactQdisc(iface ifaces.Interface, log *slog.Logger) *netlink.GenericQdisc {
	ipvlan, err := netlink.LinkByIndex(iface.Index)
	if err != nil {
		log.Error("failed to lookup ipvlan device", "index", iface.Index, "name", iface.Name, "error", err)
		return nil
	}
	qdiscAttrs := netlink.QdiscAttrs{
		LinkIndex: ipvlan.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: qdiscAttrs,
		QdiscType:  "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		if errors.Is(err, fs.ErrExist) {
			log.Warn("qdisc clsact already exists. Ignoring", "error", err)
		} else {
			log.Error("failed to create clsact qdisc on", "index", iface.Index, "name", iface.Name, "error", err)
			return nil
		}
	}

	return qdisc
}

func RegisterTC(iface ifaces.Interface, egressFD int, egressHandle uint32, egressName string,
	ingressFD int, ingressHandle uint32, ingressName string, log *slog.Logger) *TCLinks {
	links := TCLinks{
		Qdisc: GetClsactQdisc(iface, log),
	}

	if links.Qdisc == nil {
		return nil
	}

	linkIndex := links.Qdisc.QdiscAttrs.LinkIndex

	egressFilter, err := RegisterEgress(linkIndex, egressFD, egressHandle, egressName)
	if err != nil {
		log.Error("failed to install egress filters", "error", err)
	}
	links.EgressFilter = egressFilter

	ingressFilter, err := RegisterIngress(linkIndex, ingressFD, ingressHandle, ingressName)
	if err != nil {
		log.Error("failed to install ingres filters", "error", err)
	}
	links.IngressFilter = ingressFilter

	return &links
}

func RegisterEgress(linkIndex int, egressFD int, handle uint32, name string) (*netlink.BpfFilter, error) {
	return registerFilter(linkIndex, egressFD, handle, netlink.HANDLE_MIN_EGRESS, name)
}

func RegisterIngress(linkIndex int, ingressFD int, handle uint32, name string) (*netlink.BpfFilter, error) {
	return registerFilter(linkIndex, ingressFD, handle, netlink.HANDLE_MIN_INGRESS, name)
}

func registerFilter(linkIndex int, fd int, handle uint32, parent uint32, name string) (*netlink.BpfFilter, error) {
	// Fetch events on ingress
	attrs := netlink.FilterAttrs{
		LinkIndex: linkIndex,
		Parent:    parent,
		Handle:    handle,
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}

	filter := &netlink.BpfFilter{
		FilterAttrs:  attrs,
		Fd:           fd,
		Name:         name,
		DirectAction: true,
	}

	if err := netlink.FilterDel(filter); err == nil {
		log.Warn("filter already existed. Deleted it", "filter", name, "iface", linkIndex)
	}

	if err := netlink.FilterAdd(filter); err != nil {
		if errors.Is(err, fs.ErrExist) {
			log.Warn("filter already exists. Ignoring", "error", err)
		} else {
			return nil, fmt.Errorf("failed to create filter: %w", err)
		}
	}

	return filter, nil
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

func ifaceHasFilters(iface ifaces.Interface, parent uint32) bool {
	ipvlan, err := netlink.LinkByIndex(iface.Index)

	if err != nil {
		return true // be conservative assume we have filters if we can't detect them
	}

	filters, err := netlink.FilterList(ipvlan, parent)

	if err != nil {
		return true // be conservative assume we have filters if we can't detect them
	}

	return len(filters) > 0
}

func cleanupQdiscs(qdiscs map[ifaces.Interface]*netlink.GenericQdisc) {
	for iface, qd := range qdiscs {
		hasEgressFilters := ifaceHasFilters(iface, netlink.HANDLE_MIN_EGRESS)
		hasIngressFilters := ifaceHasFilters(iface, netlink.HANDLE_MIN_INGRESS)

		if hasEgressFilters || hasIngressFilters {
			log.Debug("not deleting Qdisc as it still has children", "interface", iface)
		} else {
			log.Debug("deleting Qdisc", "interface", iface)

			if err := doIgnoreNoDev(netlink.QdiscDel, netlink.Qdisc(qd)); err != nil {
				log.Error("deleting qdisc", "error", err)
			}
		}
	}
}

func cleanupFilters(filters map[ifaces.Interface]*netlink.BpfFilter, kind string) {
	for iface, ef := range filters {
		log.Debug(fmt.Sprintf("deleting %s filter", kind), "interface", iface)
		if err := doIgnoreNoDev(netlink.FilterDel, netlink.Filter(ef)); err != nil {
			log.Error(fmt.Sprintf("deleting %s filter", kind), "error", err)
		}
	}
}

func CloseTCLinks(qdiscs map[ifaces.Interface]*netlink.GenericQdisc,
	egressFilters map[ifaces.Interface]*netlink.BpfFilter,
	ingressFilters map[ifaces.Interface]*netlink.BpfFilter,
	log *slog.Logger) {
	log.Info("removing traffic control probes")

	cleanupFilters(egressFilters, "egress")
	cleanupFilters(ingressFilters, "ingress")

	// make sure this happens only after cleaning up filters, so that we don't
	// remove 3rdparty filters
	cleanupQdiscs(qdiscs)
}

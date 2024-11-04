//go:build linux

package ebpfcommon

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/grafana/beyla/pkg/internal/netolly/ifaces"
)

type TCLinks struct {
	Qdisc         *netlink.GenericQdisc
	EgressFilter  *netlink.BpfFilter
	IngressFilter *netlink.BpfFilter
}

func WatchAndRegisterTC(ctx context.Context, channelBufferLen int, register func(iface ifaces.Interface), log *slog.Logger) {
	informer := ifaces.NewWatcher(channelBufferLen)
	registerer := ifaces.NewRegisterer(informer, channelBufferLen)

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

func RegisterTC(iface ifaces.Interface, egressFD, ingressFD int, log *slog.Logger) *TCLinks {
	links := TCLinks{}

	// Load pre-compiled programs and maps into the kernel, and rewrites the configuration
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
	if err := netlink.QdiscDel(qdisc); err == nil {
		log.Warn("qdisc clsact already existed. Deleted it")
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		if errors.Is(err, fs.ErrExist) {
			log.Warn("qdisc clsact already exists. Ignoring", "error", err)
		} else {
			log.Error("failed to create clsact qdisc on", "index", iface.Index, "name", iface.Name, "error", err)
			return nil
		}
	}
	links.Qdisc = qdisc

	egressFilter, err := registerEgress(ipvlan, egressFD)
	if err != nil {
		log.Error("failed to install egress filters", "error", err)
	}
	links.EgressFilter = egressFilter

	ingressFilter, err := registerIngress(ipvlan, ingressFD)
	if err != nil {
		log.Error("failed to install ingres filters", "error", err)
	}
	links.IngressFilter = ingressFilter

	return &links
}

func registerEgress(ipvlan netlink.Link, egressFD int) (*netlink.BpfFilter, error) {
	// Fetch events on egress
	egressAttrs := netlink.FilterAttrs{
		LinkIndex: ipvlan.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  3,
		Priority:  1,
	}
	egressFilter := &netlink.BpfFilter{
		FilterAttrs:  egressAttrs,
		Fd:           egressFD,
		Name:         "tc/tc_http_egress",
		DirectAction: true,
	}
	if err := netlink.FilterDel(egressFilter); err == nil {
		log.Warn("egress filter already existed. Deleted it")
	}
	if err := netlink.FilterAdd(egressFilter); err != nil {
		if errors.Is(err, fs.ErrExist) {
			log.Warn("egress filter already exists. Ignoring", "error", err)
		} else {
			return nil, fmt.Errorf("failed to create egress filter: %w", err)
		}
	}

	return egressFilter, nil
}

func registerIngress(ipvlan netlink.Link, ingressFD int) (*netlink.BpfFilter, error) {
	// Fetch events on ingress
	ingressAttrs := netlink.FilterAttrs{
		LinkIndex: ipvlan.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}
	ingressFilter := &netlink.BpfFilter{
		FilterAttrs:  ingressAttrs,
		Fd:           ingressFD,
		Name:         "tc/tc_http_ingress",
		DirectAction: true,
	}
	if err := netlink.FilterDel(ingressFilter); err == nil {
		log.Warn("ingress filter already existed. Deleted it")
	}
	if err := netlink.FilterAdd(ingressFilter); err != nil {
		if errors.Is(err, fs.ErrExist) {
			log.Warn("ingress filter already exists. Ignoring", "error", err)
		} else {
			return nil, fmt.Errorf("failed to create ingress filter: %w", err)
		}
	}

	return ingressFilter, nil
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

func CloseTCLinks(qdiscs map[ifaces.Interface]*netlink.GenericQdisc,
	egressFilters map[ifaces.Interface]*netlink.BpfFilter,
	ingressFilters map[ifaces.Interface]*netlink.BpfFilter,
	log *slog.Logger) {
	log.Info("removing traffic control probes")

	// cleanup egress
	for iface, ef := range egressFilters {
		log.Debug("deleting egress filter", "interface", iface)
		if err := doIgnoreNoDev(netlink.FilterDel, netlink.Filter(ef)); err != nil {
			log.Error("deleting egress filter", "error", err)
		}
	}

	// cleanup ingress
	for iface, igf := range ingressFilters {
		log.Debug("deleting ingress filter", "interface", iface)
		if err := doIgnoreNoDev(netlink.FilterDel, netlink.Filter(igf)); err != nil {
			log.Error("deleting ingress filter", "error", err)
		}
	}

	// cleanup qdiscs
	for iface, qd := range qdiscs {
		log.Debug("deleting Qdisc", "interface", iface)
		if err := doIgnoreNoDev(netlink.QdiscDel, netlink.Qdisc(qd)); err != nil {
			log.Error("deleting qdisc", "error", err)
		}
	}
}

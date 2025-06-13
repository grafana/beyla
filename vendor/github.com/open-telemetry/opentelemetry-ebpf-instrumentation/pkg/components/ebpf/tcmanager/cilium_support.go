//go:build linux

package tcmanager

import (
	"errors"
	"log/slog"
	"math"
	"net"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const cilPrefix = "cil_"

func hasCiliumTCX() bool {
	if !IsTCXSupported() {
		return false
	}

	it := new(link.Iterator)

	for it.Next() {
		link := it.Take()
		defer link.Close()

		info, err := link.Info()
		if err != nil {
			continue
		}

		if info.Type != unix.BPF_LINK_TYPE_TCX {
			continue
		}

		prog, err := ebpf.NewProgramFromID(info.Program)
		if err != nil {
			continue
		}

		defer prog.Close()

		progInfo, err := prog.Info()
		if err != nil {
			continue
		}

		if strings.HasPrefix(progInfo.Name, cilPrefix) {
			return true
		}
	}

	return false
}

const ciliumNotFound = uint16(math.MaxUint16)

// returns the highest and lowest priorities of a cilium link,
// or ciliumNotFound if no cilium link is present
func ciliumLinkPriorities(link netlink.Link, parent uint32) (uint16, uint16) {
	filters, err := netlink.FilterList(link, parent)
	if err != nil {
		return ciliumNotFound, 0
	}

	minPrio := ciliumNotFound
	maxPrio := uint16(0)

	for _, filter := range filters {
		bpfFilter, ok := filter.(*netlink.BpfFilter)

		if !ok {
			continue
		}

		if !strings.HasPrefix(bpfFilter.Name, cilPrefix) {
			continue
		}

		minPrio = min(minPrio, bpfFilter.Priority)
		maxPrio = max(maxPrio, bpfFilter.Priority)
	}

	return minPrio, maxPrio
}

func ciliumTCPriorities() (uint16, uint16) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ciliumNotFound, 0
	}

	minPrio := ciliumNotFound
	maxPrio := uint16(0)

	for _, iface := range ifaces {
		link, err := netlink.LinkByIndex(iface.Index)
		if err != nil {
			continue
		}

		pMin, pMax := ciliumLinkPriorities(link, netlink.HANDLE_MIN_INGRESS)

		minPrio = min(minPrio, pMin)
		maxPrio = max(maxPrio, pMax)

		pMin, pMax = ciliumLinkPriorities(link, netlink.HANDLE_MIN_EGRESS)

		minPrio = min(minPrio, pMin)
		maxPrio = max(maxPrio, pMax)
	}

	return minPrio, maxPrio
}

func normalizeBackend(backend TCBackend) TCBackend {
	if backend != TCBackendAuto {
		return backend
	}

	if IsTCXSupported() {
		return TCBackendTCX
	}

	return TCBackendTC
}

func EnsureCiliumCompatibility(backend TCBackend) error {
	// if we are trying to attach to TCX, we will always end up attaching to
	// the chain head in front of cilium, so we should be good
	if normalizeBackend(backend) == TCBackendTCX {
		return nil
	}

	// we are using TC/Netlink attachment (TCBackendTC)

	if hasCiliumTCX() {
		return errors.New("detected Cilium TCX attachment, but Beyla has been configured to use TC")
	}

	minPrio, maxPrio := ciliumTCPriorities()

	// no Cilium program has priority 1, we are good
	if minPrio > 1 {
		return nil
	}

	// we found Cilium programs with priority 1 and other priorities, assume
	// the priority 1 programs are left-overs that we can clobber - we print a
	// warning, but do not error
	if maxPrio > 1 {
		slog.Warn("Detected potential Cilium TC left-overs!")
		return nil
	}

	// minPrio == maxPrio == 1 -> cilium should be reconfigured with
	// bpf-filter-priority >= 2
	return errors.New("detected Cilium TC with priority 1 - Cilium may clobber Beyla")
}

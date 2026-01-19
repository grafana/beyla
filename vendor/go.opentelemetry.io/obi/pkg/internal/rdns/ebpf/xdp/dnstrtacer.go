// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package xdp // import "go.opentelemetry.io/obi/pkg/internal/rdns/ebpf/xdp"

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	convenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
)

// tracer represents the main structure for DNS response tracking.
type tracer struct {
	bpfObjects *BpfObjects
	links      []*link.Link
	ringbuf    *ringbuf.Reader
}

func (t *tracer) Close() error {
	if t.bpfObjects != nil {
		t.bpfObjects.Close()
		t.bpfObjects = nil
	}

	for _, link := range t.links {
		(*link).Close()
	}

	t.links = nil

	if t.ringbuf != nil {
		t.ringbuf.Close()
	}

	return nil
}

// newTracer creates and initializes a new DNS response tracer.
// It loads the BPF program, attaches it to network interfaces, and sets up the ring buffer.
// Returns an error if any step fails.
func newTracer() (*tracer, error) {
	objects := BpfObjects{}
	spec, err := LoadBpf()
	if err != nil {
		return nil, fmt.Errorf("loading BPF data: %w", err)
	}

	// Debug events map is unsupported due to pinning
	spec.Maps["debug_events"] = &ebpf.MapSpec{
		Name:       "dummy_map",
		Type:       ebpf.RingBuf,
		Pinning:    ebpf.PinNone,
		MaxEntries: uint32(os.Getpagesize()),
	}

	if err := convenience.RewriteConstants(spec, map[string]any{
		"g_bpf_debug": true,
	}); err != nil {
		return nil, fmt.Errorf("rewriting BPF constants definition: %w", err)
	}

	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		return nil, fmt.Errorf("loading and assigning BPF objects: %w", err)
	}

	tracer := tracer{bpfObjects: &objects}

	ifaces := ifacesToAttach()

	if len(ifaces) == 0 {
		return nil, errors.New("no interfaces to attach")
	}

	log := log()

	for i := range ifaces {
		link, err := link.AttachXDP(link.XDPOptions{
			Program:   tracer.bpfObjects.DnsResponseTracker,
			Interface: ifaces[i].Index,
		})
		if err != nil {
			log.Debug("failed to attach XDP program to interface",
				"interface", ifaces[i].Name, "error", err)
			continue
		}

		log.Debug("attached to interface", "interface", ifaces[i].Name)

		tracer.links = append(tracer.links, &link)
	}

	if len(tracer.links) == 0 {
		_ = tracer.Close()
		return nil, errors.New("no interfaces found")
	}

	tracer.ringbuf, err = ringbuf.NewReader(tracer.bpfObjects.RingBuffer)
	if err != nil {
		_ = tracer.Close()
		return nil, fmt.Errorf("creating ringbuffer reader: %w", err)
	}
	return &tracer, nil
}

// ifacesToAttach returns a list of network interfaces that should be monitored.
// It filters out virtual interfaces like Docker bridges and loopback interfaces.
// TODO: connect to neto11y interface attachers
func ifacesToAttach() []net.Interface {
	ifaces, err := net.Interfaces()

	if len(ifaces) == 0 || err != nil {
		return nil
	}

	ret := make([]net.Interface, 0, len(ifaces))

	for i := range ifaces {
		if !isVirtualInterface(ifaces[i].Name) {
			ret = append(ret, ifaces[i])
		}
	}

	return ret
}

// isVirtualInterface checks if a network interface name matches known virtual interface patterns.
// It filters out Docker-related interfaces, virtual Ethernet interfaces, and loopback interfaces.
func isVirtualInterface(name string) bool {
	virtualPatterns := []string{
		"br-",    // Docker bridge interfaces
		"veth",   // Docker virtual Ethernet interfaces
		"docker", // Docker default bridge
		"lo",     // Loopback interface
	}

	for _, pattern := range virtualPatterns {
		if strings.HasPrefix(name, pattern) {
			return true
		}
	}

	return false
}

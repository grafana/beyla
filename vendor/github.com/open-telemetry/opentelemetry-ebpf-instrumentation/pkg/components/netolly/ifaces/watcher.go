//go:build linux

// Copyright Red Hat / IBM
// Copyright Grafana Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This implementation is a derivation of the code in
// https://github.com/netobserv/netobserv-ebpf-agent/tree/release-1.4

package ifaces

import (
	"context"
	"log/slog"
	"syscall"

	"github.com/vishvananda/netlink"
)

// Watcher uses system's netlink to get real-time information events about network interfaces'
// addition or removal.
type Watcher struct {
	bufLen     int
	current    map[Interface]struct{}
	interfaces func() ([]Interface, error)
	// linkSubscriber abstracts netlink.LinkSubscribe implementation, allowing the injection of
	// mocks for unit testing
	linkSubscriber func(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error
}

func NewWatcher(bufLen int) *Watcher {
	return &Watcher{
		bufLen:         bufLen,
		current:        map[Interface]struct{}{},
		interfaces:     netInterfaces,
		linkSubscriber: netlink.LinkSubscribe,
	}
}

func (w *Watcher) Subscribe(ctx context.Context) (<-chan Event, error) {
	out := make(chan Event, w.bufLen)

	go w.sendUpdates(ctx, out)

	return out, nil
}

func (w *Watcher) sendUpdates(ctx context.Context, out chan Event) {
	log := slog.With("component", "ifaces.Watcher")

	// subscribe for interface events
	links := make(chan netlink.LinkUpdate)
	if err := w.linkSubscriber(links, ctx.Done()); err != nil {
		log.Error("can't subscribe to links", "error", err)
		return
	}

	// before sending netlink updates, send all the existing interfaces at the moment of starting
	// the Watcher
	if names, err := w.interfaces(); err != nil {
		log.Error("can't fetch network interfaces. You might be missing flows", "error", err)
	} else {
		for _, name := range names {
			w.current[name] = struct{}{}
			out <- Event{Type: EventAdded, Interface: name}
		}
	}

	for link := range links {
		attrs := link.Attrs()
		if attrs == nil {
			log.Debug("received link update without attributes. Ignoring", "link", link)
			continue
		}
		iface := Interface{Name: attrs.Name, Index: attrs.Index}
		if link.Flags&(syscall.IFF_UP|syscall.IFF_RUNNING) != 0 {
			log.Debug("Interface up and running",
				"operstate", attrs.OperState,
				"flags", attrs.Flags,
				"name", attrs.Name)
			if _, ok := w.current[iface]; !ok {
				w.current[iface] = struct{}{}
				out <- Event{Type: EventAdded, Interface: iface}
			}
		} else {
			log.Debug("Interface down or not running",
				"operstate", attrs.OperState,
				"flags", attrs.Flags,
				"name", attrs.Name)
			if _, ok := w.current[iface]; ok {
				delete(w.current, iface)
				out <- Event{Type: EventDeleted, Interface: iface}
			}
		}
	}
}

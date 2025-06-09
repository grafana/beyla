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
	"time"
)

// Poller periodically looks for the network interfaces in the system and forwards Event
// notifications when interfaces are added or deleted.
type Poller struct {
	period     time.Duration
	current    map[Interface]struct{}
	interfaces func() ([]Interface, error)
	bufLen     int
}

func NewPoller(period time.Duration, bufLen int) *Poller {
	return &Poller{
		period:     period,
		bufLen:     bufLen,
		interfaces: netInterfaces,
		current:    map[Interface]struct{}{},
	}
}

func (np *Poller) Subscribe(ctx context.Context) (<-chan Event, error) {
	log := slog.With("component", "ifaces.Poller")
	log.Debug("subscribing to Interface events", "period", np.period)
	out := make(chan Event, np.bufLen)
	go func() {
		ticker := time.NewTicker(np.period)
		defer ticker.Stop()
		for {
			if ifaces, err := np.interfaces(); err != nil {
				log.Warn("fetching interface names", "error", err)
			} else {
				log.Debug("fetched interface names", "names", ifaces)
				np.diffNames(out, ifaces)
			}
			select {
			case <-ctx.Done():
				log.Debug("stopped")
				close(out)
				return
			case <-ticker.C:
				// continue after period
			}
		}
	}()
	return out, nil
}

// diffNames compares and updates the internal account of interfaces with the latest list of
// polled interfaces. It forwards Events for any detected addition or removal of interfaces.
func (np *Poller) diffNames(events chan Event, ifaces []Interface) {
	ilog := ilog()
	// Check for new interfaces
	acquired := map[Interface]struct{}{}
	for _, iface := range ifaces {
		acquired[iface] = struct{}{}
		if _, ok := np.current[iface]; !ok {
			ilog.Debug("added network interface", "interface", iface)
			np.current[iface] = struct{}{}
			events <- Event{
				Type:      EventAdded,
				Interface: iface,
			}
		}
	}
	// Check for deleted interfaces
	for iface := range np.current {
		if _, ok := acquired[iface]; !ok {
			delete(np.current, iface)
			ilog.Debug("deleted network interface", "interface", iface)
			events <- Event{
				Type:      EventDeleted,
				Interface: iface,
			}
		}
	}
}

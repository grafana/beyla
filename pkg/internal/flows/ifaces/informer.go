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
	"fmt"
	"log/slog"
	"net"
)

// EventType for an interface: added, deleted
type EventType int

const (
	EventAdded EventType = iota
	EventDeleted
)

func (e EventType) String() string {
	switch e {
	case EventAdded:
		return "Added"
	case EventDeleted:
		return "Deleted"
	default:
		return fmt.Sprintf("Unknown (%d)", e)
	}
}

func ilog() *slog.Logger {
	return slog.With("component", "ifaces.Informer")
}

// Event of a network interface, given the type (added, removed) and the interface name
type Event struct {
	Type      EventType
	Interface Interface
}

type Interface struct {
	Name  string
	Index int
}

// Informer provides notifications about each network interface that is added or removed
// from the host. Production implementations: Poller and Watcher.
type Informer interface {
	// Subscribe returns a channel that sends Event instances.
	Subscribe(ctx context.Context) (<-chan Event, error)
}

func netInterfaces() ([]Interface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("can't fetch interfaces: %w", err)
	}
	names := make([]Interface, len(ifs))
	for i, ifc := range ifs {
		names[i] = Interface{Name: ifc.Name, Index: ifc.Index}
	}
	return names, nil
}

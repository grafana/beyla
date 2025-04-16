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
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

func TestWatcher(t *testing.T) {
	ctx := t.Context()

	watcher := NewWatcher(10)
	// mock net.Interfaces and linkSubscriber to control which interfaces are discovered
	watcher.interfaces = func() ([]Interface, error) {
		return []Interface{{"foo", 1}, {"bar", 2}, {"baz", 3}}, nil
	}
	inputLinks := make(chan netlink.LinkUpdate, 10)
	watcher.linkSubscriber = func(ch chan<- netlink.LinkUpdate, _ <-chan struct{}) error {
		go func() {
			for link := range inputLinks {
				ch <- link
			}
		}()
		return nil
	}

	outputEvents, err := watcher.Subscribe(ctx)
	require.NoError(t, err)

	// initial set of fetched elements
	assert.Equal(t,
		Event{Type: EventAdded, Interface: Interface{"foo", 1}},
		getEvent(t, outputEvents, timeout))
	assert.Equal(t,
		Event{Type: EventAdded, Interface: Interface{"bar", 2}},
		getEvent(t, outputEvents, timeout))
	assert.Equal(t,
		Event{Type: EventAdded, Interface: Interface{"baz", 3}},
		getEvent(t, outputEvents, timeout))

	// updates
	inputLinks <- upAndRunning("bae", 4)
	inputLinks <- down("bar", 2)
	assert.Equal(t,
		Event{Type: EventAdded, Interface: Interface{"bae", 4}},
		getEvent(t, outputEvents, timeout))
	assert.Equal(t,
		Event{Type: EventDeleted, Interface: Interface{"bar", 2}},
		getEvent(t, outputEvents, timeout))

	// repeated updates that do not involve a change in the current track of interfaces
	// will be ignored
	inputLinks <- upAndRunning("bae", 4)
	inputLinks <- upAndRunning("foo", 1)
	inputLinks <- down("bar", 2)
	inputLinks <- down("eth0", 3)

	select {
	case ev := <-outputEvents:
		require.Failf(t, "unexpected event", "%#v", ev)
	default:
		// ok!
	}
}

func upAndRunning(name string, index int) netlink.LinkUpdate {
	return netlink.LinkUpdate{
		IfInfomsg: nl.IfInfomsg{IfInfomsg: unix.IfInfomsg{Flags: syscall.IFF_UP | syscall.IFF_RUNNING}},
		Link:      &netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: name, Index: index}},
	}
}

func down(name string, index int) netlink.LinkUpdate {
	return netlink.LinkUpdate{
		Link: &netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: name, Index: index}},
	}
}

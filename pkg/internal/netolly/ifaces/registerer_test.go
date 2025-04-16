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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

func TestRegisterer(t *testing.T) {
	ctx := t.Context()

	watcher := NewWatcher(10)
	registry := NewRegisterer(watcher, 10)
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

	outputEvents, err := registry.Subscribe(ctx)
	require.NoError(t, err)

	// initial set of fetched elements
	for i := 0; i < 3; i++ {
		getEvent(t, outputEvents, timeout)
	}
	assert.Equal(t, "foo", registry.ifaces[1])
	assert.Equal(t, "bar", registry.ifaces[2])
	assert.Equal(t, "baz", registry.ifaces[3])

	// updates
	inputLinks <- upAndRunning("bae", 4)
	inputLinks <- down("bar", 2)
	for i := 0; i < 2; i++ {
		getEvent(t, outputEvents, timeout)
	}

	assert.Equal(t, "foo", registry.ifaces[1])
	assert.NotContains(t, registry.ifaces, 2)
	assert.Equal(t, "baz", registry.ifaces[3])
	assert.Equal(t, "bae", registry.ifaces[4])

	// repeated updates that do not involve a change in the current track of interfaces
	// will be ignored
	inputLinks <- upAndRunning("fiu", 1)
	inputLinks <- down("foo", 1)
	for i := 0; i < 2; i++ {
		getEvent(t, outputEvents, timeout)
	}

	assert.Equal(t, "fiu", registry.ifaces[1])
	assert.Equal(t, "baz", registry.ifaces[3])
	assert.Equal(t, "bae", registry.ifaces[4])
}

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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const timeout = 5 * time.Second

func TestPoller(t *testing.T) {
	ctx := t.Context()

	// fake net.Interfaces implementation that returns two different sets of
	// interfaces on successive invocations
	firstInvocation := true
	var fakeInterfaces = func() ([]Interface, error) {
		if firstInvocation {
			firstInvocation = false
			return []Interface{{"foo", 1}, {"bar", 2}}, nil
		}
		return []Interface{{"foo", 1}, {"bae", 3}}, nil
	}
	poller := NewPoller(5*time.Millisecond, 10)
	poller.interfaces = fakeInterfaces

	updates, err := poller.Subscribe(ctx)
	require.NoError(t, err)
	// first poll: two interfaces are added
	assert.Equal(t,
		Event{Type: EventAdded, Interface: Interface{"foo", 1}},
		getEvent(t, updates, timeout))
	assert.Equal(t,
		Event{Type: EventAdded, Interface: Interface{"bar", 2}},
		getEvent(t, updates, timeout))
	// second poll: one interface is added and another is removed
	assert.Equal(t,
		Event{Type: EventAdded, Interface: Interface{"bae", 3}},
		getEvent(t, updates, timeout))
	assert.Equal(t,
		Event{Type: EventDeleted, Interface: Interface{"bar", 2}},
		getEvent(t, updates, timeout))
	// successive polls: no more events are forwarded
	select {
	case ev := <-updates:
		require.Failf(t, "unexpected event", "%#v", ev)
	default:
		// ok!
	}
}

func getEvent(t *testing.T, ch <-chan Event, timeout time.Duration) Event {
	t.Helper()
	select {
	case event := <-ch:
		return event
	case <-time.After(timeout):
		require.Fail(t, "timeout while waiting for an event")
	}
	return Event{}
}

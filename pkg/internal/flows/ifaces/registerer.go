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
	"net"
	"sync"
)

// Registerer is an informer that wraps another informer implementation, and keeps track of
// the currently existing interfaces in the system, accessible through the IfaceNameForIndex method.
type Registerer struct {
	m      sync.RWMutex
	inner  Informer
	ifaces map[int]string
	bufLen int
}

func NewRegisterer(inner Informer, bufLen int) *Registerer {
	return &Registerer{
		inner:  inner,
		bufLen: bufLen,
		ifaces: map[int]string{},
	}
}

func (r *Registerer) Subscribe(ctx context.Context) (<-chan Event, error) {
	innerCh, err := r.inner.Subscribe(ctx)
	if err != nil {
		return nil, err
	}
	out := make(chan Event, r.bufLen)
	go func() {
		for ev := range innerCh {
			switch ev.Type {
			case EventAdded:
				r.m.Lock()
				r.ifaces[ev.Interface.Index] = ev.Interface.Name
				r.m.Unlock()
			case EventDeleted:
				r.m.Lock()
				name, ok := r.ifaces[ev.Interface.Index]
				// prevent removing an interface with the same index but different name
				// e.g. due to an out-of-order add/delete signaling
				if ok && name == ev.Interface.Name {
					delete(r.ifaces, ev.Interface.Index)
				}
				r.m.Unlock()
			}
			out <- ev
		}
	}()
	return out, nil
}

// IfaceNameForIndex gets the interface name given an index as recorded by the underlying
// interfaces' informer. It backs up into the net.InterfaceByIndex function if the interface
// has not been previously registered
func (r *Registerer) IfaceNameForIndex(idx int) (string, bool) {
	r.m.RLock()
	name, ok := r.ifaces[idx]
	r.m.RUnlock()
	if !ok {
		iface, err := net.InterfaceByIndex(idx)
		if err != nil {
			return "", false
		}
		name = iface.Name
		r.m.Lock()
		r.ifaces[idx] = name
		r.m.Unlock()
	}
	return name, ok
}

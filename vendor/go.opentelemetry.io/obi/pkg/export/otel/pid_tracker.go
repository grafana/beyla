// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"sync"

	"go.opentelemetry.io/obi/pkg/components/svc"
)

type PidServiceTracker struct {
	pidToService map[int32]svc.UID
	servicePIDs  map[svc.UID]map[int32]struct{}
	lock         sync.Mutex
	names        map[svc.ServiceNameNamespace]svc.UID
}

func NewPidServiceTracker() PidServiceTracker {
	return PidServiceTracker{
		pidToService: map[int32]svc.UID{},
		servicePIDs:  map[svc.UID]map[int32]struct{}{},
		lock:         sync.Mutex{},
		names:        map[svc.ServiceNameNamespace]svc.UID{},
	}
}

func (p *PidServiceTracker) AddPID(pid int32, uid svc.UID) {
	p.lock.Lock()
	defer p.lock.Unlock()

	p.pidToService[pid] = uid

	pids, ok := p.servicePIDs[uid]
	if !ok {
		pids = map[int32]struct{}{}
		n := uid.NameNamespace()
		p.names[n] = uid
	}
	pids[pid] = struct{}{}
	p.servicePIDs[uid] = pids
}

func (p *PidServiceTracker) RemovePID(pid int32) (bool, svc.UID) {
	p.lock.Lock()
	defer p.lock.Unlock()

	uid, ok := p.pidToService[pid]
	if ok {
		delete(p.pidToService, pid)

		if pids, exists := p.servicePIDs[uid]; exists {
			delete(pids, pid)
			if len(pids) == 0 {
				delete(p.servicePIDs, uid)
				n := uid.NameNamespace()
				delete(p.names, n)
				return true, uid
			}
			return false, svc.UID{}
		}
	}

	return false, svc.UID{}
}

func (p *PidServiceTracker) ServiceLive(uid svc.UID) bool {
	p.lock.Lock()
	defer p.lock.Unlock()

	_, exists := p.servicePIDs[uid]

	return exists
}

func (p *PidServiceTracker) IsTrackingServerService(n svc.ServiceNameNamespace) bool {
	_, ok := p.names[n]
	return ok
}

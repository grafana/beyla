// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"sync"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
)

type PidServiceTracker struct {
	pidToService   map[app.PID]svc.UID
	pidGenerations map[app.PID]uint64
	servicePIDs    map[svc.UID]map[app.PID]struct{}
	terminatedPIDs map[app.PID]pidServiceGeneration
	lock           sync.Mutex
	names          map[svc.ServiceNameNamespace]svc.UID
}

type pidServiceGeneration struct {
	uid        svc.UID
	generation uint64
}

func NewPidServiceTracker() PidServiceTracker {
	return PidServiceTracker{
		pidToService:   map[app.PID]svc.UID{},
		pidGenerations: map[app.PID]uint64{},
		servicePIDs:    map[svc.UID]map[app.PID]struct{}{},
		terminatedPIDs: map[app.PID]pidServiceGeneration{},
		lock:           sync.Mutex{},
		names:          map[svc.ServiceNameNamespace]svc.UID{},
	}
}

func (p *PidServiceTracker) AddPID(pid app.PID, uid svc.UID) {
	p.AddPIDWithGeneration(pid, uid, 0)
}

func (p *PidServiceTracker) AddPIDWithGeneration(pid app.PID, uid svc.UID, generation uint64) {
	p.lock.Lock()
	defer p.lock.Unlock()

	delete(p.terminatedPIDs, pid)
	p.pidToService[pid] = uid
	p.pidGenerations[pid] = generation

	pids, ok := p.servicePIDs[uid]
	if !ok {
		pids = map[app.PID]struct{}{}
		n := uid.NameNamespace()
		p.names[n] = uid
	}
	pids[pid] = struct{}{}
	p.servicePIDs[uid] = pids
}

func (p *PidServiceTracker) RemovePID(pid app.PID) (bool, svc.UID) {
	p.lock.Lock()
	defer p.lock.Unlock()

	uid, ok := p.pidToService[pid]
	if ok {
		delete(p.pidToService, pid)
		p.terminatedPIDs[pid] = pidServiceGeneration{uid: uid, generation: p.pidGenerations[pid]}
		delete(p.pidGenerations, pid)

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

func (p *PidServiceTracker) TracksPID(pid app.PID) (svc.UID, bool) {
	p.lock.Lock()
	defer p.lock.Unlock()

	u, ok := p.pidToService[pid]

	return u, ok
}

func (p *PidServiceTracker) PIDLiveOrUnknown(pid app.PID, uid svc.UID, generation uint64) bool {
	p.lock.Lock()
	defer p.lock.Unlock()

	if trackedUID, ok := p.pidToService[pid]; ok {
		if !trackedUID.Equals(&uid) {
			return false
		}
		trackedGeneration := p.pidGenerations[pid]
		return trackedGeneration == 0 || generation == 0 || trackedGeneration == generation
	}
	terminatedProcess, terminated := p.terminatedPIDs[pid]
	if !terminated || !terminatedProcess.uid.Equals(&uid) {
		return true
	}
	return generation != 0 && terminatedProcess.generation != generation
}

func (p *PidServiceTracker) ReplaceUID(staleUID, newUID svc.UID) {
	p.lock.Lock()
	defer p.lock.Unlock()

	if staleUID.Equals(&newUID) {
		return
	}

	if pids, ok := p.servicePIDs[staleUID]; ok {
		for pid := range pids {
			p.pidToService[pid] = newUID
		}
		p.servicePIDs[newUID] = pids
		delete(p.servicePIDs, staleUID)
	}
}

func (p *PidServiceTracker) Count() int {
	p.lock.Lock()
	defer p.lock.Unlock()

	return len(p.pidToService)
}

func (p *PidServiceTracker) ServiceLive(uid svc.UID) bool {
	p.lock.Lock()
	defer p.lock.Unlock()

	_, exists := p.servicePIDs[uid]

	return exists
}

func (p *PidServiceTracker) IsTrackingServerService(n svc.ServiceNameNamespace) bool {
	p.lock.Lock()
	defer p.lock.Unlock()

	_, ok := p.names[n]
	return ok
}

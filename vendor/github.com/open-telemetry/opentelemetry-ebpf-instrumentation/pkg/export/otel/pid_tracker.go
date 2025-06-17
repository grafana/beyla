package otel

import (
	"sync"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/svc"
)

type PidServiceTracker struct {
	pidToService map[int32]svc.UID
	servicePIDs  map[svc.UID]map[int32]struct{}
	lock         sync.Mutex
}

func NewPidServiceTracker() PidServiceTracker {
	return PidServiceTracker{pidToService: map[int32]svc.UID{}, servicePIDs: map[svc.UID]map[int32]struct{}{}, lock: sync.Mutex{}}
}

func (p *PidServiceTracker) AddPID(pid int32, uid svc.UID) {
	p.lock.Lock()
	defer p.lock.Unlock()

	p.pidToService[pid] = uid

	pids, ok := p.servicePIDs[uid]
	if !ok {
		pids = map[int32]struct{}{}
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
				return true, uid
			}
			return false, svc.UID{}
		}
	}

	return false, svc.UID{}
}

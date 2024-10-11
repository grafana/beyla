package kube

import (
	"log/slog"
	"sync"

	"github.com/grafana/beyla-k8s-cache/pkg/informer"
	"github.com/grafana/beyla/pkg/internal/helpers/container"
)

func dblog() *slog.Logger {
	return slog.With("component", "kube.Database")
}

// Database aggregates Kubernetes information from multiple sources:
// - the informer that keep an indexed copy of the existing pods and replicasets.
// - the inspected container.Info objects, indexed either by container ID and PID namespace
// - a cache of decorated PodInfo that would avoid reconstructing them on each trace decoration
type Database struct {
	access sync.RWMutex

	containerIDs map[string]*container.Info

	// a single namespace will point to any container inside the pod
	// but we don't care which one
	namespaces map[uint32]*container.Info

	// key: pid namespace
	fetchedPodsCache map[uint32]*informer.PodInfo

	// ip to pod name matcher
	podsByIP map[string]*informer.PodInfo

	// ip to service/node name matcher
	svcNodeByIP map[string]*informer.IPInfo
}

func CreateDatabase(kubeMetadata MetadataNotifier) *Database {
	db := &Database{
		fetchedPodsCache: map[uint32]*informer.PodInfo{},
		containerIDs:     map[string]*container.Info{},
		namespaces:       map[uint32]*container.Info{},
		podsByIP:         map[string]*informer.PodInfo{},
		svcNodeByIP:      map[string]*informer.IPInfo{},
	}
	kubeMetadata.Subscribe(db)
	return db
}

func (id *Database) ID() string {
	return "unique-metadata-observer"
}

func (id *Database) On(event *informer.Event) {
	if pod := event.GetPod(); pod != nil {
		id.handlePodEvent(event.Type, pod)
	} else if ipInfo := event.GetIpInfo(); ipInfo != nil {
		id.handleIPInfoEvent(event.Type, ipInfo)
	}
}

func (id *Database) handlePodEvent(eventType informer.EventType, pod *informer.PodInfo) {
	switch eventType {
	case informer.EventType_CREATED, informer.EventType_UPDATED:
		id.updateNewPodsByIPIndex(pod)
		// TODO: if the updated message lacks an IP that was previously present in the pod
		// this might cause a memory leak, as we are not removing old entries
		// this is very unlikely and the IP could be reused by another pod later
		// TODO: also container data
	case informer.EventType_DELETED:
		id.updateDeletedPodsByIPIndex(pod)
		// TODO: also container data
	}
}

func (id *Database) handleIPInfoEvent(eventType informer.EventType, ipInfo *informer.IPInfo) {
	switch eventType {
	case informer.EventType_CREATED, informer.EventType_UPDATED:
		id.updateNewSvcNodeByIPIndex(ipInfo)
		// TODO: if the updated message lacks an IP that was previously present in the pod
		// this might cause a memory leak, as we are not removing old entries
		// this is very unlikely and the IP could be reused by another pod later
	case informer.EventType_DELETED:
		id.UpdateDeletedSvcNodeByIPIndex(ipInfo)
	}
}

func (id *Database) deleteContainer(containerID []string) {
	id.access.Lock()
	defer id.access.Unlock()
	for _, cid := range containerID {
		info, ok := id.containerIDs[cid]
		delete(id.containerIDs, cid)
		if ok {
			delete(id.fetchedPodsCache, info.PIDNamespace)
			delete(id.namespaces, info.PIDNamespace)
		}
	}
}

// AddProcess also searches for the container.Info of the passed PID
func (id *Database) AddProcess(pid uint32) {
	// TODO: hide this behind an interface for proper testing
	ifp, err := container.InfoForPID(pid)
	if err != nil {
		dblog().Debug("failing to get container information", "pid", pid, "error", err)
		return
	}

	id.access.Lock()
	defer id.access.Unlock()
	delete(id.fetchedPodsCache, ifp.PIDNamespace)
	id.namespaces[ifp.PIDNamespace] = &ifp
	id.containerIDs[ifp.ContainerID] = &ifp
}

func (id *Database) CleanProcessCaches(ns uint32) {
	id.access.Lock()
	defer id.access.Unlock()
	// Don't delete the id.namespaces, we can't tell if Add/Delete events
	// are in order. Deleting from the cache is safe, since it will be rebuilt.
	delete(id.fetchedPodsCache, ns)
}

func (id *Database) updateNewPodsByIPIndex(pod *informer.PodInfo) {
	id.access.Lock()
	defer id.access.Unlock()
	for _, ip := range pod.IpInfo.Ips {
		id.podsByIP[ip] = pod
	}
}

func (id *Database) updateDeletedPodsByIPIndex(pod *informer.PodInfo) {
	id.access.Lock()
	defer id.access.Unlock()
	for _, ip := range pod.IpInfo.Ips {
		delete(id.podsByIP, ip)
	}
}

func (id *Database) updateNewSvcNodeByIPIndex(svc *informer.IPInfo) {
	id.access.Lock()
	defer id.access.Unlock()
	for _, ip := range svc.Ips {
		id.svcNodeByIP[ip] = svc
	}
}

func (id *Database) UpdateDeletedSvcNodeByIPIndex(svc *informer.IPInfo) {
	id.access.Lock()
	defer id.access.Unlock()
	for _, ip := range svc.Ips {
		delete(id.svcNodeByIP, ip)
	}
}

func (id *Database) IPInfo(ip string) *informer.IPInfo {
	id.access.RLock()
	defer id.access.RUnlock()
	if pod, ok := id.podsByIP[ip]; ok {
		return pod.IpInfo
	}
	return id.svcNodeByIP[ip]
}

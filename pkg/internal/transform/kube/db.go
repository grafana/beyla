package kube

import (
	"fmt"
	"log/slog"
	"sync"

	"k8s.io/client-go/tools/cache"

	"github.com/grafana/beyla/pkg/internal/helpers/container"
	"github.com/grafana/beyla/pkg/internal/kube"
)

func dblog() *slog.Logger {
	return slog.With("component", "kube.Database")
}

// Database aggregates Kubernetes information from multiple sources:
// - the informer that keep an indexed copy of the existing pods and replicasets.
// - the inspected container.Info objects, indexed either by container ID and PID namespace
// - a cache of decorated PodInfo that would avoid reconstructing them on each trace decoration
type Database struct {
	informer *kube.Metadata

	cntMut       sync.Mutex
	containerIDs map[string]*container.Info

	// a single namespace will point to any container inside the pod
	// but we don't care which one
	nsMut      sync.RWMutex
	namespaces map[uint32]*container.Info

	// key: pid namespace
	podsCacheMut     sync.RWMutex
	fetchedPodsCache map[uint32]*kube.PodInfo

	// ip to pod name matcher
	podsMut  sync.RWMutex
	podsByIP map[string]*kube.PodInfo

	// ip to service name matcher
	svcMut  sync.RWMutex
	svcByIP map[string]*kube.ServiceInfo
}

func CreateDatabase(kubeMetadata *kube.Metadata) Database {
	return Database{
		fetchedPodsCache: map[uint32]*kube.PodInfo{},
		containerIDs:     map[string]*container.Info{},
		namespaces:       map[uint32]*container.Info{},
		podsByIP:         map[string]*kube.PodInfo{},
		svcByIP:          map[string]*kube.ServiceInfo{},
		informer:         kubeMetadata,
	}
}

func StartDatabase(kubeMetadata *kube.Metadata) (*Database, error) {
	db := CreateDatabase(kubeMetadata)
	db.informer.AddContainerEventHandler(&db)

	if err := db.informer.AddPodEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			db.UpdateNewPodsByIPIndex(obj.(*kube.PodInfo))
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			db.UpdateDeletedPodsByIPIndex(oldObj.(*kube.PodInfo))
			db.UpdateNewPodsByIPIndex(newObj.(*kube.PodInfo))
		},
		DeleteFunc: func(obj interface{}) {
			db.UpdateDeletedPodsByIPIndex(obj.(*kube.PodInfo))
		},
	}); err != nil {
		return nil, fmt.Errorf("can't register Database as Pod event handler: %w", err)
	}
	if err := db.informer.AddServiceIPEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			db.UpdateNewServicesByIPIndex(obj.(*kube.ServiceInfo))
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			db.UpdateDeletedServicesByIPIndex(oldObj.(*kube.ServiceInfo))
			db.UpdateNewServicesByIPIndex(newObj.(*kube.ServiceInfo))
		},
		DeleteFunc: func(obj interface{}) {
			db.UpdateDeletedServicesByIPIndex(obj.(*kube.ServiceInfo))
		},
	}); err != nil {
		return nil, fmt.Errorf("can't register Database as Service event handler: %w", err)
	}

	return &db, nil
}

// OnDeletion implements ContainerEventHandler
func (id *Database) OnDeletion(containerID []string) {
	for _, cid := range containerID {
		id.cntMut.Lock()
		info, ok := id.containerIDs[cid]
		delete(id.containerIDs, cid)
		id.cntMut.Unlock()
		if ok {
			id.podsCacheMut.Lock()
			delete(id.fetchedPodsCache, info.PIDNamespace)
			id.podsCacheMut.Unlock()
			id.nsMut.Lock()
			delete(id.namespaces, info.PIDNamespace)
			id.nsMut.Unlock()
		}
	}
}

// AddProcess also searches for the container.Info of the passed PID
func (id *Database) AddProcess(pid uint32) {
	ifp, err := container.InfoForPID(pid)
	if err != nil {
		dblog().Debug("failing to get container information", "pid", pid, "error", err)
		return
	}
	id.nsMut.Lock()
	id.namespaces[ifp.PIDNamespace] = &ifp
	id.nsMut.Unlock()
	id.cntMut.Lock()
	id.containerIDs[ifp.ContainerID] = &ifp
	id.cntMut.Unlock()
}

// OwnerPodInfo returns the information of the pod owning the passed namespace
func (id *Database) OwnerPodInfo(pidNamespace uint32) (*kube.PodInfo, bool) {
	id.podsCacheMut.RLock()
	pod, ok := id.fetchedPodsCache[pidNamespace]
	id.podsCacheMut.RUnlock()
	if !ok {
		id.nsMut.RLock()
		info, ok := id.namespaces[pidNamespace]
		id.nsMut.RUnlock()
		if !ok {
			return nil, false
		}
		pod, ok = id.informer.GetContainerPod(info.ContainerID)
		if !ok {
			return nil, false
		}
		id.podsCacheMut.Lock()
		id.fetchedPodsCache[pidNamespace] = pod
		id.podsCacheMut.Unlock()
	}
	// we check DeploymentName after caching, as the replicasetInfo might be
	// received late by the replicaset informer
	id.informer.FetchPodOwnerInfo(pod)
	return pod, true
}

func (id *Database) UpdateNewPodsByIPIndex(pod *kube.PodInfo) {
	if len(pod.IPInfo.IPs) > 0 {
		id.podsMut.Lock()
		defer id.podsMut.Unlock()
		for _, ip := range pod.IPInfo.IPs {
			id.podsByIP[ip] = pod
		}
	}
}

func (id *Database) UpdateDeletedPodsByIPIndex(pod *kube.PodInfo) {
	if len(pod.IPInfo.IPs) > 0 {
		id.podsMut.Lock()
		defer id.podsMut.Unlock()
		for _, ip := range pod.IPInfo.IPs {
			delete(id.podsByIP, ip)
		}
	}
}

func (id *Database) PodInfoForIP(ip string) *kube.PodInfo {
	id.podsMut.RLock()
	defer id.podsMut.RUnlock()
	return id.podsByIP[ip]
}

func (id *Database) UpdateNewServicesByIPIndex(svc *kube.ServiceInfo) {
	if len(svc.IPInfo.IPs) > 0 {
		id.svcMut.Lock()
		defer id.svcMut.Unlock()
		for _, ip := range svc.IPInfo.IPs {
			id.svcByIP[ip] = svc
		}
	}
}

func (id *Database) UpdateDeletedServicesByIPIndex(svc *kube.ServiceInfo) {
	if len(svc.IPInfo.IPs) > 0 {
		id.svcMut.Lock()
		defer id.svcMut.Unlock()
		for _, ip := range svc.IPInfo.IPs {
			delete(id.svcByIP, ip)
		}
	}
}

func (id *Database) ServiceInfoForIP(ip string) *kube.ServiceInfo {
	id.svcMut.RLock()
	defer id.svcMut.RUnlock()
	return id.svcByIP[ip]
}

func (id *Database) HostNameForIP(ip string) string {
	id.svcMut.RLock()
	svc, ok := id.svcByIP[ip]
	id.svcMut.RUnlock()
	if ok {
		return svc.Name
	}
	id.podsMut.RLock()
	pod, ok := id.podsByIP[ip]
	id.podsMut.RUnlock()
	if ok {
		return pod.Name
	}
	return ""
}

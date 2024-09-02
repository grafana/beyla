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

	access sync.RWMutex

	containerIDs map[string]*container.Info

	// a single namespace will point to any container inside the pod
	// but we don't care which one
	namespaces map[uint32]*container.Info
	// key: pid namespace
	fetchedPodsCache map[uint32]*kube.PodInfo

	// ip to pod name matcher
	podsByIP map[string]*kube.PodInfo

	// ip to service name matcher
	svcByIP map[string]*kube.ServiceInfo

	// ip to node name matcher
	nodeByIP map[string]*kube.NodeInfo
}

func CreateDatabase(kubeMetadata *kube.Metadata) Database {
	return Database{
		fetchedPodsCache: map[uint32]*kube.PodInfo{},
		containerIDs:     map[string]*container.Info{},
		namespaces:       map[uint32]*container.Info{},
		podsByIP:         map[string]*kube.PodInfo{},
		svcByIP:          map[string]*kube.ServiceInfo{},
		nodeByIP:         map[string]*kube.NodeInfo{},
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
			db.UpdatePodsByIPIndex(oldObj.(*kube.PodInfo), newObj.(*kube.PodInfo))
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
	if err := db.informer.AddNodeEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			db.UpdateNewNodesByIPIndex(obj.(*kube.NodeInfo))
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			db.UpdateDeletedNodesByIPIndex(oldObj.(*kube.NodeInfo))
			db.UpdateNewNodesByIPIndex(newObj.(*kube.NodeInfo))
		},
		DeleteFunc: func(obj interface{}) {
			db.UpdateDeletedNodesByIPIndex(obj.(*kube.NodeInfo))
		},
	}); err != nil {
		return nil, fmt.Errorf("can't register Database as Node event handler: %w", err)
	}

	return &db, nil
}

// OnDeletion implements ContainerEventHandler
func (id *Database) OnDeletion(containerID []string) {
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

func (id *Database) addProcess(ifp *container.Info) {
	id.access.Lock()
	defer id.access.Unlock()
	delete(id.fetchedPodsCache, ifp.PIDNamespace)
	id.namespaces[ifp.PIDNamespace] = ifp
	id.containerIDs[ifp.ContainerID] = ifp
}

// AddProcess also searches for the container.Info of the passed PID
func (id *Database) AddProcess(pid uint32) {
	ifp, err := container.InfoForPID(pid)
	if err != nil {
		dblog().Debug("failing to get container information", "pid", pid, "error", err)
		return
	}

	id.addProcess(&ifp)
}

func (id *Database) CleanProcessCaches(ns uint32) {
	id.access.Lock()
	defer id.access.Unlock()
	// Don't delete the id.namespaces, we can't tell if Add/Delete events
	// are in order. Deleting from the cache is safe, since it will be rebuilt.
	delete(id.fetchedPodsCache, ns)
}

// OwnerPodInfo returns the information of the pod owning the passed namespace
func (id *Database) OwnerPodInfo(pidNamespace uint32) (*kube.PodInfo, bool) {
	id.access.Lock()
	defer id.access.Unlock()
	pod, ok := id.fetchedPodsCache[pidNamespace]
	if !ok {
		info, ok := id.namespaces[pidNamespace]
		if !ok {
			return nil, false
		}
		pod, ok = id.informer.GetContainerPod(info.ContainerID)
		if !ok {
			return nil, false
		}
		id.fetchedPodsCache[pidNamespace] = pod
	}
	// we check DeploymentName after caching, as the replicasetInfo might be
	// received late by the replicaset informer
	id.informer.FetchPodOwnerInfo(pod)
	return pod, true
}

func (id *Database) UpdateNewPodsByIPIndex(pod *kube.PodInfo) {
	id.access.Lock()
	defer id.access.Unlock()
	if len(pod.IPInfo.IPs) > 0 {
		id.addPods(pod)
	}
}

func (id *Database) UpdateDeletedPodsByIPIndex(pod *kube.PodInfo) {
	id.access.Lock()
	defer id.access.Unlock()
	if len(pod.IPInfo.IPs) > 0 {
		id.deletePods(pod)
	}
}

func (id *Database) UpdatePodsByIPIndex(oldPod, newPod *kube.PodInfo) {
	id.access.Lock()
	defer id.access.Unlock()
	id.deletePods(oldPod)
	id.addPods(newPod)
}

func (id *Database) addPods(pod *kube.PodInfo) {
	for _, ip := range pod.IPInfo.IPs {
		id.podsByIP[ip] = pod
	}
}

func (id *Database) deletePods(pod *kube.PodInfo) {
	for _, ip := range pod.IPInfo.IPs {
		delete(id.podsByIP, ip)
		for _, cid := range pod.ContainerIDs {
			cnt, ok := id.containerIDs[cid]
			delete(id.containerIDs, cid)
			if ok {
				delete(id.namespaces, cnt.PIDNamespace)
				delete(id.fetchedPodsCache, cnt.PIDNamespace)
			}
		}
	}
}

func (id *Database) PodInfoForIP(ip string) *kube.PodInfo {
	id.access.RLock()
	defer id.access.RUnlock()
	return id.podsByIP[ip]
}

func (id *Database) UpdateNewServicesByIPIndex(svc *kube.ServiceInfo) {
	id.access.Lock()
	defer id.access.Unlock()
	if len(svc.IPInfo.IPs) > 0 {
		for _, ip := range svc.IPInfo.IPs {
			id.svcByIP[ip] = svc
		}
	}
}

func (id *Database) UpdateDeletedServicesByIPIndex(svc *kube.ServiceInfo) {
	id.access.Lock()
	defer id.access.Unlock()
	if len(svc.IPInfo.IPs) > 0 {
		for _, ip := range svc.IPInfo.IPs {
			delete(id.svcByIP, ip)
		}
	}
}

func (id *Database) ServiceInfoForIP(ip string) *kube.ServiceInfo {
	id.access.RLock()
	defer id.access.RUnlock()
	return id.svcByIP[ip]
}

func (id *Database) UpdateNewNodesByIPIndex(svc *kube.NodeInfo) {
	id.access.Lock()
	defer id.access.Unlock()
	if len(svc.IPInfo.IPs) > 0 {
		for _, ip := range svc.IPInfo.IPs {
			id.nodeByIP[ip] = svc
		}
	}
}

func (id *Database) UpdateDeletedNodesByIPIndex(svc *kube.NodeInfo) {
	id.access.Lock()
	defer id.access.Unlock()
	if len(svc.IPInfo.IPs) > 0 {
		for _, ip := range svc.IPInfo.IPs {
			delete(id.nodeByIP, ip)
		}
	}
}

func (id *Database) NodeInfoForIP(ip string) *kube.NodeInfo {
	id.access.RLock()
	defer id.access.RUnlock()
	return id.nodeByIP[ip]
}

func (id *Database) HostNameForIP(ip string) string {
	id.access.RLock()
	defer id.access.RUnlock()
	svc, ok := id.svcByIP[ip]
	if ok {
		return svc.Name
	}
	pod, ok := id.podsByIP[ip]
	if ok {
		return pod.Name
	}
	node, ok := id.nodeByIP[ip]
	if ok {
		return node.Name
	}
	return ""
}

func (id *Database) ServiceNameNamespaceForIP(ip string) (string, string) {
	id.access.RLock()
	defer id.access.RUnlock()
	svc, ok := id.svcByIP[ip]
	if ok {
		return svc.Name, svc.Namespace
	}
	pod, ok := id.podsByIP[ip]
	if ok {
		return pod.ServiceName(), pod.Namespace
	}
	node, ok := id.nodeByIP[ip]
	if ok {
		return node.Name, node.Namespace
	}
	return "", ""
}

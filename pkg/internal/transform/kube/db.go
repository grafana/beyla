package kube

import (
	"fmt"
	"log/slog"
	"time"

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
	informer Metadata

	containerIDs map[string]*container.Info
	// a single namespace will point to any container inside the pod
	// but we don't care which one
	namespaces map[uint32]*container.Info

	// key: pid namespace
	fetchedPodsCache map[uint32]*PodInfo
}

func StartDatabase(kubeConfigPath string, informersTimeout time.Duration) (*Database, error) {
	db := Database{
		fetchedPodsCache: map[uint32]*PodInfo{},
		containerIDs:     map[string]*container.Info{},
		namespaces:       map[uint32]*container.Info{},
	}
	db.informer.AddContainerEventHandler(&db)
	if err := db.informer.InitFromConfig(kubeConfigPath, informersTimeout); err != nil {
		return nil, fmt.Errorf("starting informers' database: %w", err)
	}
	return &db, nil
}

// OnRemoval implements ContainerEventHandler
func (id *Database) OnDeletion(containerID []string) {
	for _, cid := range containerID {
		if info, ok := id.containerIDs[cid]; ok {
			delete(id.namespaces, info.PIDNamespace)
		}
		delete(id.containerIDs, cid)
	}
}

// AddProcess also searches for the container.Info of the passed PID
func (id *Database) AddProcess(pid uint32) {
	ifp, err := container.InfoForPID(pid)
	if err != nil {
		dblog().Debug("failing to get container information", "pid", pid, "error", err)
		return
	}
	id.namespaces[ifp.PIDNamespace] = &ifp
	id.containerIDs[ifp.ContainerID] = &ifp
}

// OwnerPodInfo returns the information of the pod owning the passed namespace
func (id *Database) OwnerPodInfo(pidNamespace uint32) (*PodInfo, bool) {
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
	if pod.DeploymentName == "" && pod.ReplicaSetName != "" {
		if rsi, ok := id.informer.GetReplicaSetInfo(pod.ReplicaSetName); ok {
			pod.DeploymentName = rsi.DeploymentName
		}
	}
	return pod, true
}
